# SecureAI Code Analyzer

Production-grade, AI-powered Static Application Security Testing (SAST) platform. Full-stack SaaS application with real-time vulnerability scanning, advanced exploit-chain detection, CI/CD integration, RBAC, and SOC2-ready compliance controls.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Technology Stack](#technology-stack)
- [Enterprise Repository Ingestion](#enterprise-repository-ingestion)
- [Pipeline Observability & Diagnostics](#pipeline-observability--diagnostics)
- [Detection Engine](#detection-engine)
- [Accuracy Engine & False Positive Control](#accuracy-engine--false-positive-control)
- [VS Code Extension](#vs-code-extension)
- [CLI Tool](#cli-tool)
- [Production Hardening](#production-hardening)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Frontend](#frontend)
- [Backend](#backend)
- [API Reference](#api-reference)
- [Security Posture](#security-posture)
- [Configuration](#configuration)
- [Deployment](#deployment)


---

## Architecture Overview

```
                    +-------------------+
                    |   Next.js 16      |
                    |   React 19 SPA    |
                    |   Zustand 5       |
                    +--------+----------+
                             |
                       HTTPS / Cookie Auth
                       (httpOnly, Secure, SameSite)
                             |
                    +--------v----------+
                    |    FastAPI         |
                    |  API Gateway       |
                    | (Auth, Rate Limit, |
                    |  CORS, Security    |
                    |  Headers, Abuse    |
                    |  Detection)        |
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
                    | - ScanDiagnostics |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v------+  +----v--------+
     | Enterprise  |  | AI Validate |  | Git Cloner  |
     | Ingestion   |  | Perplexity  |  | ZIP Extract |
     | - PreAnalyze|  | Phi-3/Gemma |  | Diff Detect |
     | - PostFilter|  |             |  |             |
     | - SizeGuard |  +------+------+  | - Shallow   |
     | - MonoRepo  |         |         | - BlobFilter|
     +--------+---+         |         | - LFS Skip  |
              |              |         +----+--------+
              +--------------+--------------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v------+  +----v--------+
     | Rule Engine |  | Rule Exec   |  | Diagnostic  |
     | 1014 Rules  |  | Heatmap &   |  | Logging     |
     | 38 Languages|  | Regex       |  | Stage-level |
     | Enterprise  |  | Profiler    |  | Observabilty|
     +--------+---+  +------+------+  +----+--------+
              |              |              |
              +--------------+--------------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v------+  +----v--------+
     | Rule Intel  |  | Clustering  |  | Exploit     |
     | 7 Capabili- |  | Noise Redu- |  | Chain Detec-|
     | ties + 4    |  | ction + LOC |  | tion (6     |
     | Logic Dtctrs|  | Risk Density|  | Chain Types)|
     +--------+---+  +------+------+  +----+--------+
              |              |              |
              +--------------+--------------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v------+  +----v--------+
     | Dedup +     |  | Confidence  |  | Severity    |
     | Semantic    |  | Auto-Calib- |  | Normaliza-  |
     | Family Merge|  | ration      |  | tion + CVSS |
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
- **Advanced analysis pipeline**: 12-stage pipeline with clustering, exploit-chain detection, confidence calibration, and LOC-based risk density scoring
- **AI-powered validation**: LLM-based vulnerability confirmation to reduce false positives
- **Rule Intelligence**: 7 intelligence capabilities + 4 logic detectors (multi-tenant isolation, IDOR, privilege escalation)
- **Exploit-chain detection**: 6 predefined attack chains (auth bypass → RCE, SQLi → privilege escalation, SSRF → cloud metadata, etc.)
- **Noise reduction**: Vulnerability clustering (proximity-based), semantic dedup, high-density file attenuation, confidence auto-calibration
- **Enterprise repository ingestion**: 15-stage ingestion pipeline supporting 1GB repos, 50k files, monorepos, with advisory pre-analysis, optimized shallow clone, post-clone filtering, and size guards
- **Pipeline observability**: Full diagnostic logging with `logger.exception` stack traces, per-stage before/after markers, structured `[PRECHECK]`/`[CLONE]`/`[FILTER]`/`[SCAN]` prefixes, and stage-context error propagation
- **Production hardening**: Crash-safe orchestrator with per-stage try/except, advisory-only GitHub pre-checks (never blocks clone), regex C-level timeout protection, streaming 64KB ZIP extraction with bomb detection, and PendingRollbackError recovery
- **Rule execution profiler**: Per-rule heatmap with timing data, regex backtracking detection, and optimization recommendations
- **Multi-tenant isolation**: Row-level security, per-user resource quotas, tiered access
- **CI/CD native**: GitHub webhook integration, PR commenting, diff-aware scanning
- **Enterprise compliance**: SOC2 hash-chain audit logging, RBAC, GDPR data lifecycle
- **Production resilient**: Circuit breakers, saturation guards, graceful shutdown, distributed locking, memory-limit abort, pipeline-level timeout enforcement

---

## Technology Stack

### Frontend

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Next.js (App Router) | 16.1 |
| UI Library | React | 19.2 |
| State Management | Zustand | 5.0 |
| Charts | Recharts | 3.7 |
| Styling | Tailwind CSS | 4.0 |
| Language | TypeScript (strict) | 5.x |
| Icons | Lucide React | - |

### Backend

| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | FastAPI | 0.115 |
| Runtime | Python | 3.13 |
| Database | PostgreSQL (Supabase) | 15+ |
| ORM | SQLAlchemy 2.0 (async) | 2.0.35 |
| Auth | JWT (python-jose) | HS256 |
| Encryption | cryptography (Fernet + PBKDF2) | 43.0 |
| Queue | asyncio.PriorityQueue / Redis | - |
| Rate Limiting | SlowAPI | 0.1.9 |
| HTTP Client | httpx (async) | 0.27 |
| Metrics | Custom Prometheus exporter | - |

### Infrastructure

| Component | Technology |
|-----------|-----------|
| Container | Docker (multi-stage, non-root) |
| Orchestration | Kubernetes + Helm |
| Monitoring | Prometheus + Grafana |
| CI/CD | GitHub Actions / Webhooks |

---

## Enterprise Repository Ingestion

Production-grade 15-stage ingestion pipeline engineered for enterprise repositories — supports 1GB repos, 50k+ files, monorepos, CI/CD repositories, and ZIP archives with zero-freeze guarantees.

### Ingestion Pipeline

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  1. GitHub    │──>│  2. Optimized │──>│  3. Streaming │──>│  4. Post-Clone│
│  Pre-Analyzer │   │  Git Clone    │   │  Clone Handle │   │  Filtering    │
│  (advisory)   │   │  (shallow,    │   │  (async wait, │   │  (node_modules│
│  httpx async  │   │  blob filter) │   │  120s timeout)│   │  vendor, dist)│
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
        │                                                         │
        v                                                         v
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  8. Scan Task │<──│  7. Language   │<──│  6. File      │<──│  5. Size      │
│  Generation   │   │  Detection &  │   │  Discovery    │   │  Guard        │
│  (batch       │   │  Priority     │   │  Engine       │   │  (500MB       │
│  dispatch)    │   │  (sec=0,cfg=1)│   │  (streaming)  │   │  extracted)   │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
        │
        v
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  9. Monorepo  │──>│ 10. Progress  │──>│ 11. Freeze    │──>│ 12. Stage-    │
│  Safety       │   │  Tracking     │   │  Prevention   │   │  Level        │
│  (apps/pkgs/  │   │  (DB-persist, │   │  (clone tmout,│   │  Observability│
│  services)    │   │  ETA calc)    │   │  file timeout)│   │  (structured) │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
        │
        v
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ 13. Failure   │──>│ 14. Security  │──>│ 15. Pipeline  │
│  Recovery     │   │  Hardening    │   │  Integration  │
│  (per-stage   │   │  (zip-slip,   │   │  (orchestrator│
│  try/except)  │   │  path trav.)  │   │  wiring)      │
└──────────────┘   └──────────────┘   └──────────────┘
```

### Stage Details

| # | Stage | Component | Description |
|---|-------|-----------|-------------|
| 1 | **Repository Pre-Analyzer** | `repo_pre_analyzer.py` | Async GitHub API metadata fetch via httpx. Validates repo size, file count, detects large files (>10MB). Advisory-only — never blocks clone on failure. Handles rate limits (403/429) gracefully. Supports private repos via `Authorization: token` header. |
| 2 | **Optimized Git Clone** | `git_cloner.py` | Shallow clone with `--depth 1`, `--single-branch`, `--no-tags`, `--filter=blob:none`, `--recurse-submodules=no`, `GIT_LFS_SKIP_SMUDGE=1`. Cache-aware with content-addressable storage. |
| 3 | **Streaming Clone Handling** | `git_cloner.py` | `asyncio.wait_for` with 120s configurable timeout. Subprocess streaming — never loads clone output into memory. |
| 4 | **Post-Clone Filtering** | `ingestion_v2.py` | Removes `node_modules`, `vendor`, `dist`, `build`, `target`, `coverage`, `.git`, `__pycache__`, `.cache`, `.next`, `.nuxt` at root and one level deep (monorepo subprojects). |
| 5 | **Repository Size Guard** | `ingestion_v2.py` | Async extracted-size measurement via `asyncio.to_thread`. 500MB hard limit on extracted content. |
| 6 | **File Discovery Engine** | `ingestion_v2.py` | Streaming `os.scandir` walk — yields files incrementally, never builds full tree in memory. Skips binary files and ignored directories. |
| 7 | **Language Detection & Priority** | `ingestion_v2.py` | Classification with 3-tier priority: P0 (security-critical), P1 (config files), P2 (normal source). Extension-based language mapping across 38 languages. |
| 8 | **Scan Task Generation** | `scan_orchestrator.py` | Fan-out to `ChunkDispatcher` for batching, then `ParallelScanController` for concurrent execution. |
| 9 | **Monorepo Safety** | `ingestion_v2.py` | Detects `apps/`, `services/`, `packages/`, `modules/`, `libs/`, `projects/` directory patterns. Adjusts filtering depth for monorepo subprojects. |
| 10 | **Progress Tracking** | `progress_tracker.py` | DB-persisted `ScanProgressTracker` with weighted moving average ETA. Exposes phase, percent, current_file, live_vuln_count, files_scanned, total_files, eta_seconds. |
| 11 | **Freeze Prevention** | Multiple | Clone timeout (120s), per-file scan timeout (10s), worker isolation via `ProcessPoolExecutor`, pipeline-level `WORKER_TASK_TIMEOUT`, memory hard-limit abort. |
| 12 | **Observability** | `scan_orchestrator.py` | Structured log prefixes: `[PRECHECK]`, `[CLONE]`, `[FILTER]`, `[SKIP]`, `[SCAN]`. Before/after logging for every sub-stage. Full stack traces via `logger.exception`. |
| 13 | **Failure Recovery** | `scan_orchestrator.py` | Per-stage try/except with advisory vs. fatal classification. Advisory failures (precheck, post-clone filter, monorepo detection) log and continue. Fatal failures (clone, size guard) log full traceback and propagate. |
| 14 | **Security Hardening** | `zip_extractor.py` | ZIP slip protection (path traversal validation), ZIP bomb detection (compression ratio limits), streaming 64KB extraction, `_SKIP_DIRS` and `_BINARY_EXTENSIONS` filtering. |
| 15 | **Pipeline Integration** | `scan_orchestrator.py` | Full wiring: precheck → clone → post-clone filter → size guard → monorepo detection → file walk → classify → scan. Both Git and ZIP paths covered. |

### GitHub URL Parsing

Robust regex-based extraction supporting all common formats:

| URL Format | Parsed Result |
|------------|---------------|
| `https://github.com/user/repo` | `owner=user, repo=repo` |
| `https://github.com/user/repo.git` | `owner=user, repo=repo` |
| `git@github.com:user/repo.git` | `owner=user, repo=repo` |

### Ingestion Limits

| Parameter | Value | Config Key |
|-----------|-------|------------|
| Max repository size | 1,024 MB (1 GB) | `GIT_CLONE_MAX_SIZE_MB` |
| Max files per scan | 20,000 | `MAX_FILES_PER_SCAN_LARGE` |
| Clone timeout | 120 seconds | `GIT_CLONE_TIMEOUT` |
| Max extracted size (ZIP) | 200 MB | `ZIP_MAX_EXTRACTED_SIZE_MB` |
| Max files in ZIP | 20,000 | `ZIP_MAX_FILE_COUNT` |
| Post-clone size guard | 500 MB | Hard-coded in `check_extracted_size()` |
| Per-file size limit | 1 MB | `ENGINE_MAX_FILE_SIZE_BYTES` |
| Per-file scan timeout | 10 seconds | `ENGINE_PER_FILE_TIMEOUT` |
| Max request body | 512 MB | `MAX_REQUEST_BODY_MB` |
| Pre-check API timeout | 15 seconds | Hard-coded in `repo_pre_analyzer.py` |

---

## Pipeline Observability & Diagnostics

### Structured Stage Logging

Every pipeline stage emits structured before/after log entries with scan ID, stage name, duration, and contextual metadata:

```
[scan abc-123] Phase START: ingestion (0.0s elapsed)
[scan abc-123] starting precheck  repo_url=https://github.com/org/repo
[scan abc-123] [PRECHECK] repo=org/repo size=45.2MB
[scan abc-123] [PRECHECK] languages detected: ['Python', 'JavaScript', 'TypeScript']
[scan abc-123] [PRECHECK] estimated file count: 3420  large_files: False
[scan abc-123] precheck completed
[scan abc-123] starting clone  repo_url=https://github.com/org/repo  branch=main
[scan abc-123] clone completed  files=3420  temp_dir=/tmp/user/scan/abc-123
[scan abc-123] starting post-clone filtering  temp_dir=/tmp/user/scan/abc-123
[scan abc-123] [FILTER] removed node_modules (154MB)
[scan abc-123] post-clone filtering completed
[scan abc-123] starting size guard  temp_dir=/tmp/user/scan/abc-123
[scan abc-123] size guard completed
[scan abc-123] starting monorepo detection
[scan abc-123] [PRECHECK] monorepo detected: apps/, packages/
[scan abc-123] monorepo detection completed
[scan abc-123] Phase END: ingestion (duration: 12.3s, files=3420)
[scan abc-123] Phase START: classification (3420 files, 12.3s elapsed)
[scan abc-123] starting classification  files=3420
[scan abc-123] classification completed  classified=2890
[scan abc-123] Phase END: classification (duration: 1.1s, classified=2890)
[scan abc-123] Phase START: scanning (2890 classified files, 13.4s elapsed)
[scan abc-123] Scan abc-123: progress 25% — 722/2890 files, 14 findings (3.2s elapsed)
[scan abc-123] Scan abc-123: progress 50% — 1445/2890 files, 31 findings (6.1s elapsed)
[scan abc-123] Phase END: scanning (duration: 11.8s, findings=67)
```

### Exception Diagnostics

All catch blocks use `logger.exception` for full stack traces with contextual metadata:

| Context Field | Description |
|---------------|-------------|
| `scan_id` | UUID of the scan in progress |
| `stage=` | Pipeline stage name (precheck, clone, post_clone_filter, size_guard, monorepo_detection, classification, zip_extraction) |
| `repo_url=` | Repository URL being scanned |
| `branch=` | Git branch being cloned |
| `zip_path=` | ZIP file path (for archive scans) |

Example failure output:
```
[scan abc-123] clone failed  stage=clone  repo_url=https://github.com/org/repo  branch=main
Traceback (most recent call last):
  File "app/orchestration/scan_orchestrator.py", line 258, in _execute_pipeline_inner
    files, temp_dir = await ingestion.ingest_git_clone(...)
  File "app/orchestration/git_cloner.py", line 145, in clone
    raise GitCloneError("Clone timed out after 120s")
app.orchestration.git_cloner.GitCloneError: Clone timed out after 120s
```

### Error Classification

Pipeline stages are classified as **advisory** (log and continue) or **fatal** (log and propagate):

| Stage | Classification | On Failure |
|-------|---------------|------------|
| Pre-check | Advisory | Log warning + continue to clone |
| Clone | **Fatal** | Log exception + mark scan FAILED |
| Post-clone filtering | Advisory | Log exception + continue to scan |
| Size guard | **Fatal** | Log exception + mark scan FAILED |
| Monorepo detection | Advisory | Log exception + continue to classify |
| Classification | **Fatal** | Log exception + mark scan FAILED |
| ZIP extraction | **Fatal** | Log exception + mark scan FAILED |

### Rule Execution Heatmap & Regex Profiler

Post-scan profiling report generated for every scan:

| Metric | Description |
|--------|-------------|
| Per-rule timing | Execution time for each of 1,014 rules across all scanned files |
| Slow rule detection | Rules exceeding configurable threshold flagged for optimization |
| Regex backtracking | C-level timeout protection (via `regex` module) prevents catastrophic backtracking |
| Optimization report | Auto-generated recommendations for slow patterns |

### Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `active_scans` | Gauge | — | Currently running scans |
| `scans_started_total` | Counter | scan_mode, source_type, tier | Scans initiated |
| `scans_completed_total` | Counter | scan_mode, status | Scans finished (complete/failed/cancelled) |
| `scan_duration_seconds` | Histogram | scan_mode | End-to-end pipeline duration |
| `vulnerabilities_found_total` | Counter | severity | Findings by severity level |

---

## Detection Engine

### Pipeline Architecture

The scan pipeline is a deterministic, 12-stage processing chain. Each stage operates in O(n) or O(n log n) complexity with no external dependencies, AST parsing, or AI calls (AI validation is an optional async bolt-on).

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  1. File      │──>│  2. Parallel  │──>│  3. Finding   │──>│  4. Rule      │
│  Classifica-  │   │  Regex Scan   │   │  Reconstruct  │   │  Intelligence │
│  tion (38     │   │  (1,014       │   │  (EngineFin-  │   │  (7 capabil-  │
│  languages)   │   │  rules)       │   │  ding objects) │   │  ities)       │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
        │                                                         │
        v                                                         v
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  8. Severity  │<──│  7. Exploit   │<──│  6. Dedup     │<──│  5. Clustering│
│  Normaliza-   │   │  Chain Detec- │   │  (semantic +  │   │  + Confidence │
│  tion + CVSS  │   │  tion (6      │   │  exact +      │   │  Calibration  │
│               │   │  chain types) │   │  overlap)     │   │               │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
        │
        v
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  9. LOC Risk  │──>│ 10. Report   │──>│ 11. AI Valid- │──>│ 12. Final     │
│  Density      │   │  Aggregation  │   │  ation (opt)  │   │  Output       │
│  Scoring      │   │  + Executive  │   │  Perplexity/  │   │  RuleFinding  │
│               │   │  Summary      │   │  Phi-3/Gemma  │   │  List         │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

### Rule Coverage

| Category | Rules | Description |
|----------|------:|-------------|
| Injection | 218 | SQL, command, NoSQL, LDAP, SSTI, XPath, GraphQL, CRLF, template injection |
| Authentication | 178 | JWT bypass, OAuth, SAML, session fixation, IDOR, race conditions, business logic |
| DevOps | 134 | Kubernetes, Docker, Terraform, CI/CD pipeline, GitHub Actions, supply chain, cloud IAM, serverless |
| Cryptography | 104 | Weak algorithms, hardcoded keys, insecure random, TLS misconfig |
| Framework Misuse | 87 | Django, Flask, Spring, Express, Rails, ASP.NET, Laravel anti-patterns |
| Deserialization | 58 | Pickle, YAML, Java/PHP/Ruby/.NET native deserialization, XMLDecoder, SnakeYAML |
| RCE | 51 | eval/exec, process injection, template code execution |
| Secrets | 50 | API keys, passwords, tokens, private keys, platform credentials |
| Path Traversal | 47 | Directory traversal, file inclusion, symlink attacks, ZIP slip |
| XSS | 47 | Reflected, stored, DOM-based, React/Vue/Angular template injection |
| SSRF | 40 | Internal network access, cloud metadata, DNS rebinding |
| **Total** | **1,014** | **Enterprise-grade detection across 38 languages** |

### Supported Languages

Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, C++, Swift, Kotlin, Rust, SQL, Shell, YAML, Dockerfile, and 22 additional language variants with cross-language universal rules.

### Rule Intelligence Layer

Post-detection intelligence with 7 capabilities applied to every finding:

| Capability | Description |
|------------|-------------|
| Detection Layer Correlation | Layer-2 findings corroborated by nearby same-file rules get confidence boost |
| Attack Surface Classification | API-exposed vs internal vs mobile — adjusts risk exposure |
| Anti-Pattern Suppression | Line-level anti-pattern matching suppresses false positives |
| Related Rule Correlation | Nearby findings from related rules boost each other's confidence |
| Privilege Context Analysis | Flags findings in admin/root/elevated privilege contexts |
| Multi-Function Chain Matching | Detects cross-function vulnerability chains (taint paths) |
| Business Impact Assessment | Flags financial, data exposure, and compliance-relevant findings |

Plus 4 logic detectors for behavioral vulnerabilities:

| Detector | Description |
|----------|-------------|
| MT-001 / MT-009 | Multi-tenant isolation bypass (missing tenant checks in shared resources) |
| IDOR-001 | Insecure direct object reference (missing ownership validation) |
| PRIV-001 | Privilege escalation (role checks bypassed or missing) |

### Exploit-Chain Detection

6 predefined multi-stage attack chains. When all legs of a chain are present in the same file, a synthetic critical-severity finding is emitted:

| Chain | Legs | Scenario |
|-------|------|----------|
| `auth_bypass_rce` | Auth bypass + Code injection | JWT/session bypass enables remote code execution |
| `tenant_escape_export` | Tenant isolation flaw + Data export | Cross-tenant access leads to bulk data exfiltration |
| `deser_upload_chain` | File upload + Deserialization | Uploaded file triggers unsafe deserialization |
| `idor_data_leak` | IDOR + Data export | Direct object access enables unauthorized data download |
| `ssrf_cloud_metadata` | SSRF + Cloud metadata | Server-side request forgery reaches cloud instance metadata |
| `sqli_priv_escalation` | SQL injection + Privilege escalation | SQLi modifies role/permission data |
| `auth_sqli_db_takeover` | Auth bypass + SQL injection | Combined auth bypass and SQLi enables full database takeover |
| `upload_deser_rce` | File upload + Deserialization | Uploaded file deserialized unsafely leading to RCE |
| `ssrf_cloud_cred_theft` | SSRF + Cloud metadata | SSRF to cloud metadata endpoint steals IAM credentials |
| `cicd_secret_exfil` | CI/CD injection + Secrets access | Pipeline injection combined with secret access for exfiltration |

### Enterprise Detection Capabilities (v4.0)

The v4.0 rulebase expansion adds enterprise-grade detection across 7 new YAML files:

| Capability | Rules | Coverage |
|------------|------:|----------|
| **Enterprise Injection** | 15 | NoSQL (MongoDB/PyMongo/Mongoose), LDAP, XPath, GraphQL, SSTI (Jinja2/Mako/Freemarker/Pebble/EJS/Pug), CRLF injection |
| **Enterprise Auth** | 14 | JWT alg:none/confusion/weak-secret, OAuth redirect_uri/state, SAML signature bypass, session fixation, cookie flags, IDOR, race conditions (TOCTOU) |
| **Enterprise Deserialization** | 5 | XMLDecoder, SnakeYAML, PHP unserialize, YAML unsafe_load, .NET BinaryFormatter/SoapFormatter/NetDataContractSerializer |
| **Supply Chain** | 5 | npm/pip dependency confusion, malicious lifecycle scripts, pip install from git/URL, lockfile tampering |
| **Cloud Security** | 6 | AWS IAM privilege escalation, admin access policies, S3 public buckets, K8s wildcard ClusterRole, privileged containers, Docker socket mount |
| **Advanced CI/CD** | 14 | Pipeline command injection, secret exposure in logs, GitHub Actions permissions, pwn-request (pull_request_target), Terraform state/credentials, Helm template injection, Docker capabilities, serverless IAM, unauthenticated serverless endpoints |
| **Business Logic** | 10 | Missing rate limiting (Python/Java), client-controlled payment amounts, negative quantity bypass, workflow state/step skipping, coupon replay |
| **Cross-Rule Correlation** | 4 | Auth bypass + SQLi → DB takeover, file upload + deser → RCE, SSRF + cloud metadata → credential theft, CI/CD injection + secrets → exfiltration |

### Rulebase Quality Improvements

| Improvement | Detail |
|-------------|--------|
| **Anti-pattern bug fix** | Dict-format anti-patterns in rule_loader.py now correctly extract pattern strings instead of stringifying dicts |
| **Regex optimization** | Eliminated O(n²) backtracking in SQL injection WHERE patterns (bounded to `[^'"]{0,200}`) |
| **RCE pattern fix** | Replaced triple `.*?` branches with `[^)]{0,150}` in os.system/os.popen rules |
| **3-layer detection** | All new rules classified: Layer 1 (simple pattern), Layer 2 (context-aware), Layer 3 (advanced logic) |
| **Metadata standards** | All new rules include confidence, CWE, OWASP, detection_layer, attack_surface_type, vulnerability_family, cross_rule_intelligence |

### Noise Reduction

Multiple layers reduce false positives and finding noise:

| Layer | Mechanism |
|-------|-----------|
| **Vulnerability Clustering** | Groups findings by file + semantic family within ±25 lines. Representative finding carries `evidence_count`. Max cluster size: 50 |
| **Confidence Auto-Calibration** | Context signals (detection depth, attack surface, privilege) and corroborating rules boost confidence. Formula: `base + min(signals×5, 15) + min(corr×7, 20)` |
| **Semantic Dedup** | Merges findings from the same vulnerability family in overlapping code regions |
| **High-Density Attenuation** | Files with >30 findings get confidence penalty on non-critical findings (excess × 3.0, capped at 25) |
| **Exploit-Chain Scaling** | Diminishing returns on repeated chain findings in the same file |

### Result Accuracy Pipeline

A 10-part pipeline that transforms SecureAI from a noisy pattern scanner into a developer-trustworthy security analyzer. Eliminates duplicate findings, prevents scanning of non-source files, and ensures rules only fire in the correct context.

#### Pipeline Stages

```
┌────────────────┐   ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│ 1. Scan Scope  │──>│ 2. Rule Context│──>│ 3. File Type   │──>│ 4. Self-Scan   │
│ Control        │   │ Gating         │   │ Filtering      │   │ Protection     │
│ (dir/file      │   │ (framework     │   │ (language →    │   │ (report +      │
│ exclusions)    │   │ detection)     │   │ extension)     │   │ lock files)    │
└────────────────┘   └────────────────┘   └────────────────┘   └────────────────┘
        │                                                              │
        v                                                              v
┌────────────────┐   ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│ 8. Finding     │<──│ 7. Confidence  │<──│ 6. Confidence  │<──│ 5. Strict      │
│ Aggregation    │   │ Filtering      │   │ Recalibration  │   │ Deduplication  │
│ (N occurrences)│   │ (threshold)    │   │ (pattern-only  │   │ (rule+file+    │
│               │   │                │   │ downgrade)     │   │ line+pattern)  │
└────────────────┘   └────────────────┘   └────────────────┘   └────────────────┘
        │
        v
┌────────────────┐   ┌────────────────┐
│ 9. Report      │──>│ 10. Output     │
│ Integrity      │   │ Improvements   │
│ Protection     │   │ (clean, deduped│
│               │   │ aggregated)    │
└────────────────┘   └────────────────┘
```

#### Part 1 — Scan Scope Control (`engine/scan_scope.py`)

Strict exclusion rules. The scanner NEVER scans:

| Category | Excluded |
|----------|----------|
| **Dependency dirs** | `node_modules/`, `bower_components/`, `vendor/` |
| **Build output** | `dist/`, `build/`, `.next/`, `out/`, `target/` |
| **VCS** | `.git/`, `.svn/`, `.hg/` |
| **Python artifacts** | `__pycache__/`, `venv/`, `.venv/` |
| **Scanner output** | `secureai-report.json`, `*-report.json`, `*-results.json` |
| **Lock files** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `composer.lock`, etc. |
| **Environment** | `.env`, `.env.local`, `.env.production` |

#### Part 2 — Rule Context Gating (`engine/context_gating.py`)

Framework-specific rules only execute when the correct project context exists:

| Framework | Detection Method |
|-----------|-----------------|
| **Next.js** | `next.config.js` exists OR `package.json` contains `"next"` |
| **Flask** | `requirements.txt` contains `flask` OR source has `from flask` |
| **FastAPI** | `requirements.txt` contains `fastapi` OR source has `from fastapi` |
| **Django** | `manage.py` exists OR `requirements.txt` contains `django` |
| **Spring** | `pom.xml` contains `spring-boot` OR source has `import org.springframework` |
| **Express** | `package.json` contains `"express"` |
| **Rails** | `Gemfile` contains `rails` |
| **Laravel** | `artisan` exists OR `composer.json` contains `laravel/framework` |

#### Part 3 — Finding Deduplication (`engine/finding_aggregation.py`)

A finding is unique by `(rule_id, file_path, line_number, matched_pattern)`. Exact duplicates are discarded.

#### Part 4 — Finding Aggregation (`engine/finding_aggregation.py`)

Identical findings grouped with occurrence counts:

```
Before: SQL Injection detected    ×3 separate findings
After:  SQL Injection detected (3 occurrences) — Lines: L12, L45, L89
```

#### Part 5 — Self-Scan Protection (`engine/scan_scope.py`)

The scanner never scans its own output files, rule files, or configuration files. Report files are detected by name pattern matching.

#### Part 6 — File Type Filtering (`engine/context_gating.py`)

Rules only run on supported file types:

| Rule Language | Valid Extensions |
|--------------|-----------------|
| Python | `.py`, `.pyw` |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs`, `.vue`, `.svelte` |
| TypeScript | `.ts`, `.tsx`, `.mts` |
| Java | `.java` |
| HTML | `.html`, `.htm`, `.ejs`, `.jinja`, `.jinja2` |

JSON and lock files never have code-analysis rules run on them.

#### Part 7 — Result Noise Reduction

Confidence-based filtering:

| Mode | Threshold | Behavior |
|------|-----------|----------|
| Default | Medium (40+) | Only medium/high confidence findings shown |
| `--show-low-confidence` | Low (0+) | All findings shown |
| `--confidence-threshold high` | High (70+) | Only high-confidence findings shown |

#### Part 8 — Confidence Recalibration (`engine/result_accuracy.py`)

| Signal | Confidence Level |
|--------|-----------------|
| Pattern match only (no context) | Low — downgraded |
| Pattern + variable name in context | Medium — preserved |
| Pattern + user input indicator | High — boosted to 70+ |
| Pattern + taint path confirmed | High — boosted to 70+ |

#### Part 9 — Report Integrity Protection

Scanner output files are excluded from future scans. The report output path itself is excluded from discovery.

#### Part 10 — Output Improvements

Final report includes:
- No duplicate findings
- No scanning of dependency directories
- No scanning of generated reports
- Accurate rule activation based on framework detection
- Aggregated results with occurrence counts and affected line numbers
- `total_occurrences` count in summary (sum of all occurrences across aggregated groups)
- Pipeline metadata showing which accuracy stages were applied

### Repository Risk Scoring

LOC-normalized risk scoring replaces naive penalty counting:

| Metric | Formula | Description |
|--------|---------|-------------|
| `repository_loc` | `Σ non-blank non-comment lines` | Approximate logical lines of code |
| `risk_density` | `Σ(severity_weight × confidence/100) / LOC` | Weighted risk per line of code |
| `normalized_security_score` | `100 × e^(−4000 × risk_density)` | Exponential decay score (0–100) |
| `findings_per_kloc` | `total_findings / (LOC / 1000)` | Finding density per thousand lines |

### Production Hardening

Critical stability fixes applied to the scan pipeline:

| Fix | Component | Description |
|-----|-----------|-------------|
| **Crash-safe orchestrator** | `scan_orchestrator.py` | Per-stage try/except with advisory vs. fatal classification. Advisory stages (precheck, post-clone filter, monorepo) log and continue. Fatal stages (clone, size guard, classification) log full traceback and propagate. |
| **PendingRollbackError recovery** | `scan_orchestrator.py` | SQLAlchemy session rollback handling prevents cascade failures after DB errors |
| **YAML timeout protection** | `detection_engine.py` | `regex` module C-level timeout replaces Python-level `re` module. Prevents catastrophic backtracking on pathological YAML input. |
| **ZIP bomb detection** | `zip_extractor.py` | Compression ratio monitoring during streaming extraction. Aborts if ratio exceeds safe threshold. |
| **ZIP slip protection** | `zip_extractor.py` | Path traversal validation on every extracted filename — rejects paths containing `..` or absolute paths |
| **Binary file detection** | `ingestion.py` | NULL-byte heuristic on first 8KB chunk prevents binary files from entering scan pipeline |
| **Memory-limit abort** | `parallel_controller.py` | `MemoryLimitExceeded` exception hard-stops the scan if worker memory exceeds threshold |
| **Pipeline timeout** | `scan_orchestrator.py` | `asyncio.wait_for` wraps entire pipeline with `WORKER_TASK_TIMEOUT`. On timeout, scan marked FAILED automatically. |
| **Streaming upload** | `scans.py` | 256KB chunked streaming upload — never loads full request body into memory |
| **Advisory pre-check** | `repo_pre_analyzer.py` | GitHub API pre-check never raises exceptions. Rate limits (403/429), 404s, and network errors all return partial results. Pipeline always proceeds to clone. |

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
* **Problem:** Security scanners frequently match pattern matches inside comments, multiline docstrings, unit tests, code examples, or log statements (Root Cause #1 — responsible for 48.4% of all False Positives).
* **Fix:** The engine pre-computes an $O(1)$ string-literal map (`_build_string_line_map`) for every file prior to scanning. Any regex match falling on a line inside double/single triple-quotes (`"""` / `'''`), string assignments, or multiline comments is automatically skipped.

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

### Extension Configurations
Configure settings in VS Code (`settings.json`):

| Setting Key | Type | Default | Description |
| :--- | :--- | :---: | :--- |
| `secureai.enabled` | `boolean` | `true` | Enable/disable real-time security scanning. |
| `secureai.scanOnSave` | `boolean` | `true` | Scan files automatically when saved. |
| `secureai.scanOnType` | `boolean` | `true` | Scan files as you type (debounced). |
| `secureai.scanDelay` | `number` | `800` | Delay in milliseconds before scanning after typing (debounce). |
| `secureai.minSeverity` | `string` | `"low"` | Minimum severity to report (`critical`, `high`, `medium`, `low`, `info`). |
| `secureai.minConfidence` | `number` | `40` | Minimum confidence (0-100) to report a finding. |

### Commands
Access these commands via the VS Code Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):
* `SecureAI: Scan Current File` — Run a full scan on the active file immediately.
* `SecureAI: Toggle Real-Time Scanning` — Instantly turn real-time scans on/off.
* `SecureAI: Clear All Findings` — Clear all underlines and diagnostics.

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
This generates `secureai-scanner-0.1.0.vsix` inside the extension directory, which can be installed in VS Code via "Extensions" -> "Install from VSIX..." or via command line:
```bash
code --install-extension secureai-scanner-0.1.0.vsix
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
> [!NOTE]
> Installing the CLI registers the `secureai` executable on your path and attempts to automatically install the `@openai/codex` CLI (requires Node.js 22+) for optional AI-powered false-positive removal.

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

### CLI Options

| Argument | Options / Defaults | Description |
| :--- | :--- | :--- |
| `-o`, `--output` | Default: `secureai-report.json` | Path where the scanned JSON report is saved. |
| `--severity` | `info`, `low`, `medium`, `high`, `critical` | Minimum severity threshold to report. |
| `--lang` | Comma-separated (e.g. `python,javascript`) | Limit scanner execution to specific languages. |
| `--json` | Flag | Output raw JSON results directly to stdout instead of formatted terminal text. |
| `--confidence-threshold` | `low`, `medium`, `high` (Default: `medium`) | Minimum confidence level to report. |
| `--show-low-confidence` | Flag | Include low-confidence results in the output report. |
| `--workers` | Integer | Number of parallel worker threads to run (default: auto-detected). |
| `--ai` | Flag | Enable AI-powered verification with OpenAI Codex to filter false positives. |
| `--ai-timeout` | Default: `180` | Timeout in seconds for AI scanner calls. |

---

## Project Structure

```
security/
├── backend/                          # FastAPI backend
│   ├── app/
│   │   ├── main.py                   # Application + lifespan
│   │   ├── api/                      # Route handlers
│   │   │   ├── auth.py               #   OAuth (Google, GitHub)
│   │   │   ├── scans.py              #   Scan CRUD + lifecycle
│   │   │   ├── repos.py              #   Repository management
│   │   │   ├── cicd.py               #   CI/CD pipeline management
│   │   │   ├── webhooks.py           #   GitHub webhook receiver
│   │   │   ├── usage.py              #   Usage & billing metrics
│   │   │   ├── compliance.py         #   SOC2 + GDPR endpoints
│   │   │   └── metrics.py            #   Prometheus /metrics
│   │   ├── auth/
│   │   │   ├── jwt_handler.py        #   Token create/decode/revoke
│   │   │   ├── permissions.py        #   RBAC permission system
│   │   │   ├── oauth_google.py       #   Google OAuth flow
│   │   │   └── oauth_github.py       #   GitHub OAuth flow
│   │   ├── core/
│   │   │   ├── config.py             #   Pydantic BaseSettings
│   │   │   ├── security.py           #   Fernet encryption
│   │   │   ├── kms.py                #   KMS abstraction
│   │   │   └── logging.py            #   Structured logging
│   │   ├── models/                   #   SQLAlchemy ORM models
│   │   ├── middleware/               #   Security middleware stack
│   │   ├── orchestration/            #   Scan pipeline orchestration
│   │   │   ├── scan_orchestrator.py   #     Master 6-phase pipeline coordinator
│   │   │   ├── session_manager.py     #     Scan state machine + cancel events
│   │   │   ├── progress_tracker.py    #     DB-persisted progress + ETA
│   │   │   ├── repo_pre_analyzer.py   #     Async GitHub API pre-check (advisory)
│   │   │   ├── git_cloner.py          #     Secure shallow clone + cache
│   │   │   ├── parallel_controller.py #     Concurrent batch scanning
│   │   │   ├── chunk_dispatcher.py    #     File-to-batch assignment
│   │   │   ├── report_aggregator.py   #     Finding→report generation
│   │   │   ├── ai_validation_queue.py #     AI validation orchestration
│   │   │   ├── cleanup_service.py     #     Temp directory cleanup
│   │   │   ├── scan_diagnostics.py    #     Background diagnostic tasks
│   │   │   └── zip_guard.py           #     ZIP pre-validation
│   │   ├── services/
│   │   │   ├── ingestion.py           #     File ingestion utilities
│   │   │   ├── ingestion_v2.py        #     Enterprise repo ingestion service
│   │   │   ├── zip_extractor.py       #     Secure streaming ZIP extraction
│   │   │   ├── cost_estimator.py      #     Token usage estimation
│   │   │   ├── usage_aggregator.py    #     Usage recording + quotas
│   │   │   └── metrics.py             #     Prometheus metrics registry
│   │   ├── queue/                    #   Distributed queue backends
│   │   ├── worker/                   #   Standalone scan workers
│   │   ├── services/                 #   Business logic services
│   │   ├── scanner/                  #   Legacy scanner bridge
│   │   ├── ai/                       #   AI provider integrations
│   │   ├── schemas/                  #   Pydantic schemas
│   │   └── db/                       #   Database session factory
│   ├── engine/                       # Static analysis engine
│   │   ├── models.py                 #   EngineRule + EngineFinding dataclasses
│   │   ├── detection_engine.py       #   Core pattern matching
│   │   ├── rule_loader.py            #   YAML rule index (LRU cached)
│   │   ├── pipeline.py               #   12-stage scan pipeline
│   │   ├── rule_intelligence.py      #   7 capabilities + 4 logic detectors
│   │   ├── clustering.py             #   Vulnerability clustering + noise reduction
│   │   ├── confidence_calibration.py #   Context-aware confidence adjustment
│   │   ├── exploit_chains.py         #   6 exploit-chain pattern detectors
│   │   ├── deduplication.py          #   Semantic family merge + exact/overlap dedup
│   │   ├── severity.py               #   CVSS scoring + LOC risk density
│   │   ├── streaming_scanner.py      #   Large file streaming
│   │   ├── file_classifier.py        #   Language detection (16 languages)
│   │   ├── rule_profiler.py          #   Per-rule execution heatmap + optimization
│   │   ├── worker.py                 #   Process pool scan workers
│   │   ├── ai_validation.py          #   AI confidence scoring
│   │   ├── scan_scope.py             #   Scan scope control + self-scan protection
│   │   ├── context_gating.py         #   Framework-aware rule activation + file type filtering
│   │   ├── finding_aggregation.py    #   Finding dedup + aggregation engine
│   │   ├── result_accuracy.py        #   Result accuracy pipeline orchestrator
│   │   └── framework_detector.py     #   Project-level framework detection
│   ├── rules/                        # 1,014 YAML detection rules (38 languages)
│   │   ├── injection/                #   SQL, NoSQL, LDAP, XPath, GraphQL, SSTI, CRLF (218 rules)
│   │   ├── auth/                     #   Auth, JWT, OAuth, SAML, IDOR, business logic (178 rules)
│   │   ├── devops/                   #   K8s, Docker, Terraform, CI/CD, cloud, supply chain (134 rules)
│   │   ├── crypto/                   #   Weak crypto, keys (104 rules)
│   │   ├── framework_misuse/         #   Framework-specific (87 rules)
│   │   ├── deserialization/          #   Unsafe deserialization (58 rules)
│   │   ├── rce/                      #   Remote code execution (51 rules)
│   │   ├── secrets/                  #   API keys, passwords (50 rules)
│   │   ├── path_traversal/           #   Directory traversal (47 rules)
│   │   ├── xss/                      #   Reflected, stored, DOM (47 rules)
│   │   └── ssrf/                     #   Server-side request forgery (40 rules)
│   ├── k8s/                          # Kubernetes deployment
│   │   ├── helm/                     #   Helm chart + templates
│   │   └── monitoring/               #   Grafana + alert rules
│   ├── tests/                        # 58 integration tests
│   ├── Dockerfile                    # Multi-stage, non-root
│   ├── docker-compose.yml
│   └── requirements.txt
│
├── src/                              # Next.js frontend
│   ├── app/
│   │   ├── layout.tsx                #   Root layout + providers
│   │   ├── globals.css               #   CSS variables + design system
│   │   ├── page.tsx                  #   Landing page
│   │   ├── login/page.tsx            #   OAuth login (Google/GitHub)
│   │   ├── dashboard/page.tsx        #   Stats + recent activity
│   │   ├── scan/page.tsx             #   New scan (paste/upload/repo)
│   │   ├── results/page.tsx          #   Scan results + charts
│   │   ├── history/page.tsx          #   Scan history + filtering
│   │   ├── cicd/page.tsx             #   CI/CD pipeline management
│   │   ├── compliance/page.tsx       #   SOC2 compliance dashboard
│   │   ├── admin/page.tsx            #   Admin panel (role-gated)
│   │   └── settings/page.tsx         #   User profile + preferences
│   │
│   ├── components/
│   │   ├── layout/
│   │   │   ├── AppShell.tsx          #   Authenticated page wrapper
│   │   │   ├── Header.tsx            #   Nav bar with RBAC-gated items
│   │   │   └── ClientProviders.tsx   #   Provider composition root
│   │   ├── auth/
│   │   │   ├── AuthGuard.tsx         #   Route protection
│   │   │   ├── ApiEventInterceptor.tsx#  Global API event handler
│   │   │   ├── LogoutModal.tsx       #   Logout confirmation
│   │   │   └── RepoSelector.tsx      #   GitHub repo picker
│   │   ├── ui/
│   │   │   ├── Badge.tsx             #   Severity/status badges
│   │   │   ├── EmptyState.tsx        #   Empty content placeholder
│   │   │   ├── Modal.tsx             #   Reusable modal dialog
│   │   │   ├── ProgressBar.tsx       #   Animated progress bar
│   │   │   ├── Skeleton.tsx          #   Loading skeleton
│   │   │   └── Tabs.tsx              #   Tabbed navigation
│   │   ├── scan/
│   │   │   ├── CodePasteEditor.tsx   #   Code paste with highlighting
│   │   │   ├── FileUploader.tsx      #   Drag-and-drop file upload
│   │   │   ├── ProgressTracker.tsx   #   Real-time scan progress
│   │   │   ├── ScanConfigPanel.tsx   #   Scan depth/categories/AI
│   │   │   └── UsageSummary.tsx      #   Quota usage display
│   │   ├── cicd/
│   │   │   ├── ConnectPipelineModal.tsx # Pipeline creation wizard
│   │   │   ├── PipelineDetail.tsx    #   Pipeline detail + baseline
│   │   │   └── PipelineList.tsx      #   Pipeline listing
│   │   └── results/
│   │       ├── ChartsSection.tsx     #   Severity distribution charts
│   │       ├── ExecutiveSummary.tsx   #   Security posture overview
│   │       ├── RepoRiskIntelligence.tsx # Repo-level risk analysis
│   │       ├── VulnerabilityModal.tsx #   Finding detail modal
│   │       └── VulnerabilityTable.tsx #   Sortable finding list
│   │
│   ├── api/
│   │   ├── apiClient.ts              #   Fetch wrapper + interceptors
│   │   ├── auth.ts                   #   Auth API methods
│   │   ├── scans.ts                  #   Scan API methods
│   │   ├── cicd.ts                   #   CI/CD API methods
│   │   ├── compliance.ts             #   Compliance API methods
│   │   ├── usage.ts                  #   Usage API methods
│   │   ├── metrics.ts                #   Metrics API methods
│   │   └── index.ts                  #   Barrel export
│   │
│   ├── store/
│   │   ├── authStore.ts              #   Auth state + RBAC helpers
│   │   ├── scanStore.ts              #   Scan lifecycle state
│   │   └── historyStore.ts           #   Scan history state
│   │
│   └── lib/
│       ├── api.ts                    #   Legacy HTTP client
│       └── errors.ts                 #   Error types + handling
│
├── next.config.ts                    # CSP headers, env-aware
├── eslint.config.mjs                 # Security ESLint rules
├── package.json
├── tsconfig.json
└── tailwind.config.ts
```

---

## Getting Started

### Prerequisites

- Python 3.13+
- Node.js 20+
- PostgreSQL 15+ (or Supabase project)
- Git

### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate         # Windows
# source venv/bin/activate    # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your database URL, OAuth credentials, API keys

# Run development server
python -m uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload
```

### Frontend Setup

```bash
# From project root
npm install

# Configure API URL
# Edit .env.local:
#   NEXT_PUBLIC_API_URL=http://localhost:5000/api/v1

# Start development server
npm run dev
```

The frontend runs at `http://localhost:3000`, the backend at `http://localhost:5000`.

### Docker

```bash
cd backend
docker build -t secureai-analyzer .
docker run -p 5000:8000 --env-file .env secureai-analyzer
```

---

## Frontend

### Pages

| Route | Description | Auth Required |
|-------|-------------|:------------:|
| `/` | Landing page with feature overview and CTA | No |
| `/login` | OAuth login (Google and GitHub) with error handling | No |
| `/dashboard` | Overview with scan stats, recent scans, risk chart | Yes |
| `/scan` | New scan via code paste, file upload, or GitHub repo | Yes |
| `/results` | Detailed results with charts, vulnerability table, executive summary | Yes |
| `/history` | Scan history with search, filtering, and pagination | Yes |
| `/cicd` | CI/CD pipeline management, baseline tracking, risk timeline | Yes |
| `/compliance` | SOC2 compliance dashboard, audit log viewer, GDPR controls | Yes (admin/auditor) |
| `/admin` | Admin panel for user management and system settings | Yes (admin) |
| `/settings` | User profile, display name, avatar, account stats | Yes |

### API Client Layer

The frontend uses a centralized API client (`src/api/apiClient.ts`) with:

- **Cookie-based auth**: All requests use `credentials: 'include'` for httpOnly JWT cookies
- **Event bus**: Cross-cutting error handling via `onApiEvent()` for 401, 403, 429, 402, 5xx
- **Type-safe methods**: `apiGet<T>()`, `apiPost<T>()`, `apiPut<T>()`, `apiDelete<T>()`
- **Image URL sanitization**: `safeImageUrl()` blocks `javascript:` and `data:` protocol URLs

Dedicated API modules: `auth.ts`, `scans.ts`, `cicd.ts`, `compliance.ts`, `usage.ts`, `metrics.ts`

### State Management

Three Zustand 5 stores with selective subscriptions:

| Store | Responsibilities |
|-------|-----------------|
| `authStore` | User session, OAuth login/logout, `checkAuth()`, RBAC helpers (`hasRole()`, `hasPermission()`) |
| `scanStore` | Scan lifecycle (start, poll, complete), progress tracking, result caching |
| `historyStore` | Paginated scan history, search, filtering |

### Key Components

| Component | Purpose |
|-----------|---------|
| `AppShell` | Authenticated layout wrapper with header and content area |
| `Header` | Navigation bar with RBAC-gated menu items (Compliance for admin/auditor, Admin for admin) |
| `AuthGuard` | Route protection with automatic redirect to login |
| `ApiEventInterceptor` | Global listener for 401/403/429/5xx events with toast notifications |
| `ScanConfigPanel` | Scan depth selector, category toggles, AI validation settings |
| `FileUploader` | Drag-and-drop file upload (blocks `.env` files) |
| `CodePasteEditor` | Code paste textarea with language detection |
| `ProgressTracker` | Real-time scan progress with stage indicators |
| `VulnerabilityTable` | Sortable, filterable vulnerability listing with severity badges |
| `ChartsSection` | Severity distribution pie/bar charts via Recharts |
| `ExecutiveSummary` | High-level security posture overview with risk scores |
| `RepoRiskIntelligence` | Repository-level risk aggregation and trend analysis |
| `PipelineDetail` | CI/CD pipeline configuration with masked webhook secrets |
| `ConnectPipelineModal` | Pipeline creation wizard with repo selection |
| `LogoutModal` | Confirmation dialog for logout action |
| `RepoSelector` | GitHub repository picker for scan and CI/CD setup |
| `ClientProviders` | Provider composition root (React DevTools disabled in production) |

### Design System

CSS custom properties defined in `globals.css`:

- **Colors**: Brand palette, severity colors (critical/high/medium/low/info), semantic text/bg/border tokens
- **Typography**: Inter font family, consistent size scale
- **Components**: `.card`, `.btn`, `.btn-primary`, `.btn-secondary`, `.btn-dark`, `.badge`, `.input` classes
- **Animations**: `fadeInUp`, `spin`, `pulse` keyframes
- **Responsive**: Mobile-first with breakpoints via Tailwind

---

## Backend

See [`backend/README.md`](backend/README.md) for comprehensive backend documentation including:

- Static analysis engine (1,014 rules, 38 languages)
- 12-stage scan pipeline (detection → intelligence → clustering → dedup → exploit chains → severity → risk density)
- Enterprise repository ingestion (15-stage pipeline: precheck → clone → filter → size guard → monorepo → discovery → classify)
- Pipeline observability (structured stage logging, `logger.exception` stack traces, before/after markers)
- Rule Intelligence layer (7 capabilities + 4 logic detectors)
- Rule Execution Heatmap & Regex Performance Profiler
- Exploit-chain detection (6 multi-stage attack patterns)
- Noise reduction framework (clustering, calibration, semantic dedup, density attenuation)
- LOC-based repository risk scoring (exponential decay model)
- Production hardening (crash-safe orchestrator, YAML timeout, ZIP bomb detection, PendingRollbackError recovery)
- Distributed worker architecture (memory/Redis queue backends)
- CI/CD webhook integration (diff scanning, PR comments, baseline tracking)
- SOC2 compliance (hash-chain audit logging, RBAC, GDPR)
- Kubernetes Helm chart and monitoring
- Full API reference
- 58 integration tests

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/auth/google` | Google OAuth redirect |
| `GET` | `/auth/github` | GitHub OAuth redirect |
| `GET` | `/api/v1/auth/me` | Current user profile |
| `POST` | `/api/v1/auth/refresh` | Refresh access token |
| `POST` | `/api/v1/auth/logout` | Revoke tokens + clear cookies |
| `PUT` | `/api/v1/auth/user/update` | Update display name |
| `GET` | `/api/v1/auth/user/stats` | Account statistics |

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

### Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/compliance/status` | SOC2 readiness report |
| `GET` | `/api/v1/compliance/audit-log` | Query audit log |
| `POST` | `/api/v1/compliance/audit-verify` | Verify hash-chain integrity |
| `POST` | `/api/v1/compliance/gdpr/delete-my-data` | GDPR right-to-be-forgotten |
| `GET` | `/api/v1/compliance/gdpr/export-my-data` | GDPR data portability |

### Health & Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe |
| `GET` | `/health/ready` | Readiness probe |
| `GET` | `/health/deep` | Deep dependency check |
| `GET` | `/metrics` | Prometheus metrics |

---

## Security Posture

### Authentication

- **OAuth 2.0 server-side flow**: Google and GitHub (authorization code exchange happens on the backend)
- **httpOnly cookies**: JWT access (30min) and refresh (7 days) tokens stored as httpOnly, Secure, SameSite=Lax cookies
- **Token revocation**: JTI-based blacklist in database
- **No localStorage tokens**: Tokens never exposed to JavaScript

### Frontend Security

| Control | Implementation |
|---------|---------------|
| CSP | Environment-aware Content-Security-Policy (strict in production, relaxed in dev) |
| XSS prevention | `safeImageUrl()` blocks `javascript:` and `data:` protocol URLs in image sources |
| File upload | `.env` files blocked from upload accept list |
| API error handling | Global interceptor prevents infinite redirect loops on 401 |
| Memory safety | `cancelled` flags and `AbortController` patterns in all async `useEffect` hooks |
| DevTools | React DevTools injection disabled in production builds |
| ESLint | `no-eval`, `no-implied-eval`, `no-new-func`, `no-script-url`, `no-debugger` enforced |
| Token transport | Refresh token sent in POST body, not URL query string |

### Backend Security

| Control | Implementation |
|---------|---------------|
| Encryption at rest | Fernet AES-128-CBC with PBKDF2 key derivation |
| RBAC | 4 roles (admin, auditor, developer, user) with 9 granular permissions |
| Rate limiting | Per-endpoint, per-user rate limits via SlowAPI |
| Request size limit | Configurable max body size enforcement (512MB for ZIPs, 5MB for files) |
| Saturation guard | 503 when memory or queue pressure exceeds threshold |
| Security headers | CSP, HSTS, X-Content-Type-Options, X-Frame-Options on every response |
| Abuse detection | Behavioral anomaly detection middleware |
| Audit logging | SHA-256 hash-chain linked audit entries (SOC2) |
| GDPR | Self-service data deletion and export |
| ZIP security | Streaming extraction with slip protection, bomb detection, binary filtering, path traversal validation |
| Clone security | Shallow clone only, LFS skip, submodule skip, blob filter, per-user isolated temp directories, automatic cleanup |
| Ingestion isolation | Per-user temp directory (`/tmp/{user_id}/{scan_id}/`), post-scan cleanup via `CleanupService` |
| Regex safety | C-level timeout via `regex` module prevents ReDoS on pathological input patterns |
| Advisory pre-check | GitHub API failures never block scan pipeline — rate limits, 404s, network errors all handled gracefully |

---

## Configuration

### Frontend Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:5000/api/v1` | Backend API base URL |

### Backend Environment

See [`backend/README.md`](backend/README.md) for the full configuration reference with 100+ variables. Key variables:

| Variable | Description |
|----------|-------------|
| `JWT_SECRET_KEY` | JWT signing key (min 16 chars) |
| `PPLX_API_KEY` | Perplexity AI API key |
| `ENCRYPTION_KEY` | Data encryption key (min 16 chars) |
| `DATABASE_URL` | PostgreSQL connection string |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `CORS_ORIGINS` | Allowed CORS origins (JSON array) |

### Ingestion & Scan Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `GIT_CLONE_MAX_SIZE_MB` | `1024` | Maximum repository size for cloning (1 GB) |
| `GIT_CLONE_TIMEOUT` | `120` | Git clone timeout in seconds |
| `MAX_FILES_PER_SCAN_LARGE` | `20000` | Maximum files per scan |
| `ZIP_MAX_EXTRACTED_SIZE_MB` | `200` | Maximum extracted ZIP archive size |
| `ZIP_MAX_FILE_COUNT` | `20000` | Maximum files in a ZIP archive |
| `MAX_FILE_SIZE_MB` | `1` | Per-file size limit |
| `MAX_REQUEST_BODY_MB` | `512` | Maximum HTTP request body size |
| `ENGINE_PER_FILE_TIMEOUT` | `10` | Per-file scan timeout in seconds |
| `ENGINE_MAX_FILE_SIZE_BYTES` | `1048576` | Maximum file size for engine processing (1 MB) |
| `BATCH_MAX_SIZE_MB` | Configurable | Maximum batch size for parallel scanning |
| `BATCH_MAX_FILES` | Configurable | Maximum files per scan batch |
| `WORKER_TASK_TIMEOUT` | Configurable | Overall pipeline timeout |

---

## Deployment

### Development

```bash
# Terminal 1: Backend
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 5000 --reload

# Terminal 2: Frontend
npm run dev
```

### Production Build

```bash
# Frontend
npm run build
npm start

# Backend (Docker)
cd backend
docker build -t secureai-analyzer .
docker run -p 8000:8000 --env-file .env secureai-analyzer
```

### Kubernetes

```bash
cd backend/k8s/helm
helm install secureai . -n secureai --create-namespace \
  --set secrets.jwtSecret=<...> \
  --set secrets.encryptionKey=<...> \
  --set postgresql.host=<db-host>
```

See [`backend/README.md`](backend/README.md) for full Helm chart documentation, HPA configuration, monitoring setup, and alert rules.

---

## Testing

### Backend
```bash
cd backend
python -m pytest tests/ -x -v     # 58 integration tests
python rule-tests/run_tests.py     # Rule validation tests
```

### CLI
```bash
cd backend
# Verify CLI command is registered
secureai version
secureai rules --lang python
secureai scan cli/ --severity medium
```

### VS Code Extension
```bash
cd backend/extension
# Run extension validation tests
npm test
```

### Frontend
```bash
npx tsc --noEmit                   # TypeScript type check
npm run build                      # Production build (validates all routes)
npx eslint . --max-warnings 0     # Lint check
```

---

## License

Proprietary. All rights reserved.
