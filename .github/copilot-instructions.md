# Copilot Instructions

## Project Overview

**dunedain** is an open-source, self-hostable software supply chain security platform. It scans containers, source directories, and dependency manifests for known vulnerabilities using Trivy, Grype, and the [osv.dev](https://osv.dev) API. It enforces configurable security policies, generates CycloneDX SBOMs, provides a real-time dashboard for prioritizing and remediating findings, and integrates with ticketing systems (Jira) for two-way vulnerability lifecycle management.

---

## Repository Structure

```
.
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app entry point, lifespan, CORS, 11 routers, default policy seeding, Alembic upgrade
│   │   ├── models.py            # SQLAlchemy ORM models (17 models)
│   │   ├── schemas.py           # Pydantic v2 request/response schemas (~40 schemas)
│   │   ├── database.py          # SQLAlchemy engine + SessionLocal (SQLite default, PostgreSQL in Docker)
│   │   ├── celery_app.py        # Celery application + configuration + beat schedule
│   │   ├── routers/
│   │   │   ├── scans.py         # Scan CRUD + findings/sbom/policy-results sub-resources
│   │   │   ├── policies.py      # Policy CRUD + on-demand evaluate endpoint
│   │   │   ├── reports.py       # Dashboard stats + audit log
│   │   │   ├── sbom.py          # SBOM ingest + get-by-id
│   │   │   ├── settings.py      # App settings key-value store
│   │   │   ├── vulns.py         # OSV.dev proxy (deep-dive)
│   │   │   ├── registries.py    # Registry CRUD + sync/test/repos sub-resources
│   │   │   ├── teams.py         # Team CRUD + ownership rules + team dashboard
│   │   │   ├── integrations.py  # Integration CRUD + tickets + bulk tickets + webhook registration + ticket comments
│   │   │   ├── webhooks.py      # Jira webhook receiver + event log + retry
│   │   │   └── automation.py    # Automation rule CRUD + trigger list + execution history + toggle
│   │   ├── repositories/
│   │   │   ├── base.py          # BaseRepository[T] generic CRUD
│   │   │   └── repos.py         # 20 concrete repository classes
│   │   ├── services/
│   │   │   ├── scanner.py       # All scanner logic (Trivy, Grype, OSV, manifest parsing)
│   │   │   ├── policy.py        # Policy rule evaluation
│   │   │   ├── risk.py          # Risk score computation + finding prioritization
│   │   │   ├── sbom.py          # CycloneDX SBOM generation + SBOM parsing (CycloneDX/SPDX)
│   │   │   ├── cache.py         # File-based scan result cache
│   │   │   ├── registry.py      # Container registry connectivity (ACR, Docker Hub, GHCR)
│   │   │   ├── msrc.py          # Microsoft Security Response Center advisory cache
│   │   │   ├── ticketing/
│   │   │   │   ├── __init__.py      # get_provider() factory
│   │   │   │   ├── base.py          # TicketingProvider ABC + dataclasses
│   │   │   │   ├── jira_provider.py # JiraProvider implementation
│   │   │   │   ├── field_mapper.py  # Finding→Jira field transformation
│   │   │   │   ├── auto_tickets.py  # Auto-ticket creation for teams
│   │   │   │   ├── registry.py      # Provider registry (pluggable)
│   │   │   │   └── webhook_processor.py  # Jira webhook parsing + trigger classification
│   │   │   └── automation/
│   │   │       ├── __init__.py
│   │   │       └── engine.py        # Automation rule evaluation + action execution
│   │   └── tasks/
│   │       ├── scan.py          # Celery task: run_scan (full scan pipeline)
│   │       ├── registry_sync.py # Celery tasks: sync_registry, sync_all_registries
│   │       ├── msrc_refresh.py  # Celery task: refresh_msrc_cache
│   │       └── automation.py    # Celery tasks: process_webhook_event, fire_internal_event
│   ├── migrations/
│   │   ├── env.py               # Alembic environment (render_as_batch=True)
│   │   └── versions/
│   │       ├── 0001_column_additions.py
│   │       ├── 0002_teams_ownership.py
│   │       ├── 0003_sla_global_only.py
│   │       ├── 0004_vulnerability_instances.py
│   │       ├── 0005_integrations.py
│   │       ├── 0006_team_auto_tickets.py
│   │       └── 0007_webhooks_automation_rules.py
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── test_api.py
│   │   └── test_services.py
│   ├── alembic.ini
│   ├── Dockerfile               # Includes Trivy v0.69.3 + Grype v0.109.0 baked in
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.tsx              # Router setup (15 routes), QueryClient config
│   │   ├── types.ts             # All shared TypeScript interfaces (~25 interfaces)
│   │   ├── utils.ts             # Helpers (parseUTC, formatting)
│   │   ├── api/                 # Axios client + 11 domain API wrappers
│   │   │   ├── client.ts
│   │   │   ├── scans.ts
│   │   │   ├── policies.ts
│   │   │   ├── reports.ts
│   │   │   ├── sbom.ts
│   │   │   ├── vulns.ts
│   │   │   ├── settings.ts
│   │   │   ├── registries.ts
│   │   │   ├── teams.ts
│   │   │   ├── integrations.ts
│   │   │   ├── webhooks.ts
│   │   │   └── automation.ts
│   │   ├── components/
│   │   │   ├── Layout.tsx             # Sidebar (11 nav items) + outlet
│   │   │   ├── FindingCard.tsx        # Collapsible card + OsvDetailPanel
│   │   │   ├── PolicyRuleEditor.tsx   # 4 policy rule types
│   │   │   ├── StatusBadge.tsx
│   │   │   ├── SeverityBadge.tsx
│   │   │   ├── FieldMappingEditor.tsx # Integration field mapping editor
│   │   │   └── AutomationRuleEditor.tsx  # Automation rule builder
│   │   └── pages/
│   │       ├── Dashboard.tsx          # Stats + bar chart + top vulns + recent scans
│   │       ├── Scans.tsx              # Scan list with create/delete/rerun modals
│   │       ├── ScanDetail.tsx         # 3-tab detail (Findings / SBOM / Policy Results)
│   │       ├── Policies.tsx           # Policy CRUD with PolicyRuleEditor
│   │       ├── SBOMViewer.tsx         # Standalone SBOM component table
│   │       ├── AuditLog.tsx           # Filterable audit event log
│   │       ├── Settings.tsx           # scanner_backend toggle
│   │       ├── Workers.tsx            # Rack-unit visualisation of 3 workers × 8 slots
│   │       ├── Registries.tsx         # Registry CRUD + repository browsing
│   │       ├── SeedScans.tsx          # Synthetic scan generation + progress
│   │       ├── Teams.tsx              # Team CRUD + ownership rules + auto-ticket config
│   │       ├── TeamDashboard.tsx      # Team-specific findings + SLA tracking
│   │       ├── Integrations.tsx       # Integration CRUD + tickets + webhooks + comments
│   │       └── AutomationRules.tsx    # Automation rule CRUD + execution history
│   ├── Dockerfile               # nginx-based static host
│   └── package.json
├── docs/
│   └── database-portability.md  # PostgreSQL migration guide
├── docker-compose.yml
└── .github/workflows/
    └── ci.yml
```

---

## Tech Stack

| Layer | Technologies |
|---|---|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy (ORM only, no raw SQL), SQLite (local) / PostgreSQL (Docker), Pydantic v2, httpx, Celery, Redis, Alembic |
| **Frontend** | React 19, TypeScript, Vite, @tanstack/react-query v5, Axios, Recharts, React Router v6, Lucide icons |
| **Scanner engines** | Trivy v0.69.3 (baked into Docker image), Grype v0.109.0 (baked into Docker image), osv.dev batch API |
| **SBOM** | CycloneDX 1.4 JSON (generated); also parses SPDX JSON on ingest |
| **Ticketing** | Jira (REST API via JiraProvider); pluggable provider ABC for ServiceNow/Linear/GitHub Issues |
| **Deployment** | Docker Compose — 4 services: `redis`, `backend`, `worker` (3 replicas), `frontend` (nginx) |

---

## Development Setup

### Backend (local)

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 1337
```

### Frontend (local)

```bash
cd frontend
npm install
npm run dev
```

### Full stack (Docker Compose)

```bash
docker compose up -d
```

| Service | URL |
|---|---|
| Web UI | http://localhost |
| API | http://localhost:8001 |
| API docs | http://localhost:8001/docs |

> **Note:** In Docker Compose the backend is mapped to host port `8001` (container port `1337`). The frontend nginx proxies API calls to the backend service internally.

---

## Build & Test

### Backend tests (pytest)

```bash
cd backend
pip install -r requirements.txt pytest pytest-asyncio httpx
pytest tests/ -v
```

### Frontend build & lint

```bash
cd frontend
npm ci
npm run build   # TypeScript compile + Vite bundle
npm run lint    # ESLint
```

---

## Async Architecture: Celery + Redis

All scan execution is **asynchronous**. The FastAPI backend creates a `Scan` row with `status="pending"` and immediately returns `202 Accepted`. The actual scan runs in a Celery worker.

### Configuration (`celery_app.py`)

- **Broker / backend:** Redis — env vars `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` (default: `redis://localhost:6379/0`)
- `task_acks_late=True` — task acknowledged only after completion (safe against worker crash)
- `worker_prefetch_multiplier=1` — one task at a time per worker process
- Soft time limit: 29 min (SIGTERM); hard limit: 30 min (SIGKILL)
- Queue name: `scans`
- **Task includes:** `app.tasks.scan`, `app.tasks.registry_sync`, `app.tasks.msrc_refresh`, `app.tasks.automation`

### Task Routes

| Task | Queue |
|---|---|
| `app.tasks.scan.run_scan` | `scans` |
| `app.tasks.registry_sync.sync_registry` | `scans` |
| `app.tasks.registry_sync.sync_all_registries` | `scans` |
| `app.tasks.msrc_refresh.refresh_msrc_cache` | `scans` |
| `app.tasks.automation.process_webhook_event` | `scans` |
| `app.tasks.automation.fire_internal_event` | `scans` |

### Beat Schedule

| Name | Task | Schedule |
|---|---|---|
| `sync-all-registries-every-5-minutes` | `sync_all_registries` | Every 5 minutes |
| `refresh-msrc-cache-daily` | `refresh_msrc_cache` | Daily at 3 AM UTC |

### Docker Compose scaling

```yaml
worker:
  command: celery -A app.celery_app worker --loglevel=info --concurrency=8 -Q scans
  deploy:
    replicas: 3
```

3 worker containers × 8 concurrent tasks = 24 maximum parallel scans.

### The `run_scan` Celery task (`tasks/scan.py`)

The pipeline runs in this exact order:

1. Set `scan.status = "running"`, commit
2. Compute cache key (`SHA-256` of `"scan_type:target"`); check file cache (skip if `force=True`)
3. If cache miss: dispatch to the appropriate scanner function (`scan_dependencies`, `scan_container`, or `scan_source`)
4. Write raw findings to cache (`set_cache`)
5. Persist `Finding` rows with deduplication, `db.flush()`
6. Call `prioritize_findings` — sorts findings by `risk_score` descending in memory
7. Upsert `VulnerabilityInstance` rows (first-seen / last-seen tracking)
8. Evaluate all enabled `Policy` rows; persist `PolicyResult` rows
9. Generate CycloneDX SBOM; persist `SBOM` row
10. Auto-assign team via ownership rules (glob pattern matching on target)
11. Auto-create tickets for teams with `auto_create_tickets=True` and severity above threshold
12. Set `scan.status = "completed"`, set `scanner_engine`, `base_image`, `base_image_chain`, `completed_at`, commit
13. Write `AuditLog` entry with action `"scan_completed"`
14. Fire internal events: `fire_internal_event.delay("scan_completed", context)` and `fire_internal_event.delay("policy_violated", context)` for each failed policy

On any unhandled exception the task sets `scan.status = "failed"` and re-raises.

### The `process_webhook_event` Celery task (`tasks/automation.py`)

1. Load `WebhookEvent` from DB, set status to `"processing"`
2. Run `process_webhook_event()`: parse Jira payload, update matched ticket state (status, assignee, priority)
3. Run `classify_event_triggers()`: determine which automation triggers apply (e.g. `jira_status_changed`)
4. If no triggers and no matched ticket: set status `"ignored"`, return
5. Build context dict with ticket/finding/team details
6. For each trigger: call `evaluate_automation_rules(db, trigger, context)`
7. Mark event as `"processed"`, write audit log
8. On failure: set status `"failed"`, retry up to 3 times with 10s delay

### The `fire_internal_event` Celery task (`tasks/automation.py`)

Called by the scan pipeline when internal events occur. Calls `evaluate_automation_rules()` directly. Retries up to 2 times with 5s delay.

---

## Scanner Engine System (`services/scanner.py`)

### Scanner selection

The `scanner_backend` app setting controls which engine is used:

| Value | Behaviour |
|---|---|
| `auto` (default) | Try Trivy, then Grype, then OSV-only |
| `trivy` | Use Trivy + OSV enrichment only |
| `grype` | Use Grype + OSV enrichment only |

The preference is read from the `AppSetting` table via `_get_scanner_preference()` at scan time. Individual scans can override this with `scanner_override`.

### `scan_container(image_name)` → `(findings, engine, base_image, base_image_chain)`

1. **Trivy** (`trivy image --format json`): parse results, extract language packages, enrich with OSV, merge, extract base image from OCI labels / history
2. **Grype** (`grype <image> --output json`): same pattern with Grype JSON format
3. **Dockerfile static parse** (`_parse_dockerfile`): if target is a Dockerfile path, extract inline `pip install`/`npm install` commands and referenced manifests, then call OSV

### `scan_source(source_path)` → `(findings, engine)`

1. **Trivy** (`trivy fs <dir>`)
2. **Grype** (`grype dir:<dir>`)
3. **Manifest parsing**: recursively finds `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`, `pom.xml` under the directory

### `scan_dependencies(packages)` → `list[dict]`

Direct OSV batch query. Used for dependency scan type and as the enrichment step after Trivy/Grype.

### Manifest parsers (`_parse_manifest`)

| File | Ecosystems | Notes |
|---|---|---|
| `requirements.txt` | PyPI | Handles `==`, `>=`, `~=`, etc. |
| `package.json` | npm | Parses `dependencies` + `devDependencies`; strips semver range prefixes |
| `go.mod` | Go | Parses `require` blocks (single and multi-line) |
| `Cargo.toml` | crates.io | Parses `[dependencies]` + `[dev-dependencies]`; handles string and table specs |
| `pom.xml` | Maven | Skips `${...}` variable versions |

### `_parse_dockerfile(path)` details

- Collapses line continuations (`\\\n`) before parsing
- Handles `&&`-chained `RUN` commands
- Extracts `pip install pkg==version`, `pip3`, `python -m pip`
- Extracts `npm install pkg@version`
- Detects `COPY requirements.txt` / `COPY package*.json` and parses those manifests
- Skips multi-stage `COPY --from=<stage>` instructions

### Finding deduplication (`_merge_findings`)

Primary scanner findings come first; OSV-enrichment findings are appended only if `(vulnerability_id, package_name)` is not already present. When duplicates are found, the finding with the higher CVSS score is preferred.

### Base image extraction

Both `_extract_base_image_trivy` and `_extract_base_image_grype`:
1. Check `org.opencontainers.image.base.name` OCI label (most reliable)
2. Walk image history entries to detect `FROM scratch` layers
3. Fall back to first `RepoTags` entry if no label

### Ecosystem mappings

Trivy type → OSV ecosystem (e.g. `python-pkg` → `PyPI`, `node-pkg` → `npm`, `go` → `Go`, `cargo` → `crates.io`, `jar`/`pom` → `Maven`). Grype artifact type → OSV ecosystem (e.g. `python` → `PyPI`, `go-module` → `Go`, `rust-crate` → `crates.io`, `java-archive` → `Maven`). OS-level package types are intentionally excluded from OSV enrichment.

---

## Risk Score (`services/risk.py`)

```
base = cvss_score  (if present)  else  severity_proxy
       CRITICAL→9.0, HIGH→7.0, MEDIUM→4.0, LOW→1.0, UNKNOWN→2.0

score = base
if exploitable: score *= 1.5
if reachable:   score *= 1.3
final = min(score, 10.0)  # capped at 10
```

`prioritize_findings(findings)` returns findings sorted by `risk_score` descending.

---

## Database Models (`models.py`)

All primary keys are UUIDs stored as `String`. All `DateTime` columns store UTC. 17 models total.

### `Registry`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `name` | String | |
| `url` | String | Registry URL |
| `type` | Enum | `acr`, `docker_hub`, `ghcr`, `generic` |
| `auth_method` | Enum | `managed_identity`, `username_password`, `none` |
| `username` | String | Nullable |
| `password` | String | Nullable |
| `auto_sync` | Boolean | Default True |
| `created_at` | DateTime | |
| `last_synced_at` | DateTime | Nullable |
| `repository_cache` | JSON | `{repo: [tag, ...], ...}` |

Relationships: `scans` (1:N)

### `Scan`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `name` | String | |
| `scan_type` | Enum | `container`, `dependency`, `source` |
| `target` | String | Image name, path, or package target |
| `status` | Enum | `pending`, `running`, `completed`, `failed`, `unsupported` |
| `created_at` | DateTime | |
| `completed_at` | DateTime | Nullable |
| `error_message` | String | Nullable; human-readable reason for failed/unsupported |
| `scanner_engine` | String | `trivy`, `grype`, or `osv`; nullable |
| `scanner_override` | String | Nullable; force a specific backend for this scan |
| `base_image` | String | Container scans only; nullable |
| `base_image_chain` | JSON | List of layer ancestry names; nullable |
| `packages` | JSON | Stored for dependency reruns; nullable |
| `registry_id` | String FK → registries | Nullable |
| `team_id` | String FK → teams | Nullable; auto-assigned via ownership rules |

Relationships: `findings` (1:N, `cascade="all, delete-orphan"`), `sbom` (1:1, `cascade="all, delete-orphan"`), `policy_results` (1:N, `cascade="all, delete-orphan"`), `registry` (N:1), `team` (N:1)

### `Finding`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `scan_id` | String FK → scans | |
| `package_name` | String | |
| `package_version` | String | |
| `package_ecosystem` | String | |
| `vulnerability_id` | String | e.g. `CVE-2023-1234`, `GHSA-...` |
| `severity` | Enum | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NEGLIGIBLE`, `UNKNOWN` |
| `cvss_score` | Float | Nullable |
| `description` | Text | Truncated to 500 chars from scanner output |
| `fix_version` | String | Nullable |
| `is_fixed` | Boolean | |
| `reachable` | Boolean | |
| `exploitable` | Boolean | |
| `risk_accepted` | Boolean | Default False |
| `risk_accepted_at` | DateTime | Nullable |
| `risk_score` | Float | |
| `aliases` | JSON | List of alternate IDs |
| `references` | JSON | List of URLs |

Relationships: `scan` (N:1), `tickets` (1:N)

### `Policy`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `name` | String | |
| `description` | String | Nullable |
| `enabled` | Boolean | |
| `rules` | JSON | List of rule dicts |
| `action` | Enum | `block`, `warn`, `audit` |
| `created_at` | DateTime | |
| `updated_at` | DateTime | |

### `PolicyResult`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `scan_id` | String FK → scans | |
| `policy_id` | String FK → policies | |
| `passed` | Boolean | |
| `violations` | JSON | List of violation dicts |
| `evaluated_at` | DateTime | |

### `SBOM`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `scan_id` | String FK → scans | |
| `format` | Enum | `cyclonedx`, `spdx` |
| `spec_version` | String | e.g. `"1.4"` |
| `content` | JSON | Raw SBOM document |
| `components_count` | Integer | |
| `generated_at` | DateTime | |

### `AuditLog`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `action` | String | `scan_completed`, `policy_created`, `sbom_ingested`, `integration_created`, `ticket_created`, `webhook_registered`, `webhook_processed`, `automation_rule_created` |
| `resource_type` | String | `scan`, `policy`, `sbom`, `integration`, `ticket`, `webhook_event`, `automation_rule` |
| `resource_id` | String | Nullable |
| `details` | JSON | |
| `created_at` | DateTime | |

### `Team`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `name` | String | Unique |
| `description` | String | Nullable |
| `contact_email` | String | Nullable |
| `integration_id` | String FK → integrations | Nullable; linked ticketing integration |
| `auto_create_tickets` | Boolean | Default False |
| `ticket_severity_threshold` | Enum | Default `HIGH`; minimum severity for auto-ticketing |
| `created_at` | DateTime | |
| `updated_at` | DateTime | |

Relationships: `ownership_rules` (1:N, cascade), `scans` (1:N), `integration` (N:1)

### `OwnershipRule`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `team_id` | String FK → teams | |
| `pattern` | String | Glob pattern matched against scan target |
| `scan_type` | String | Nullable; restrict to specific scan type |
| `priority` | Integer | Higher wins when multiple rules match |
| `description` | String | Nullable |
| `created_at` | DateTime | |

### `VulnerabilityInstance`

Tracks unique vulnerability instances across scans. Keyed on `(vulnerability_id, package_name, target)` via unique constraint. Upserted after each scan completes.

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `vulnerability_id` | String | Indexed |
| `package_name` | String | |
| `target` | String | |
| `severity` | Enum | |
| `cvss_score` | Float | Nullable |
| `package_version` | String | Latest observed |
| `package_ecosystem` | String | |
| `is_fixed` | Boolean | |
| `fix_version` | String | Nullable |
| `risk_score` | Float | |
| `first_seen_at` | DateTime | |
| `last_seen_at` | DateTime | |
| `first_scan_id` | String FK → scans | SET NULL on delete |
| `last_scan_id` | String FK → scans | SET NULL on delete |
| `team_id` | String FK → teams | SET NULL on delete; derived from scan's team |

### `AppSetting`

| Column | Type | Notes |
|---|---|---|
| `key` | String PK | |
| `value` | String | |
| `description` | String | Nullable |
| `updated_at` | DateTime | |

Currently defined key: `scanner_backend` (default: `"auto"`).

### `Integration`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `name` | String | |
| `provider` | Enum | `jira`, `servicenow`, `linear`, `github_issues` |
| `enabled` | Boolean | |
| `base_url` | String | e.g. `https://mycompany.atlassian.net` |
| `auth_method` | Enum | `basic`, `api_token`, `oauth2`, `pat` |
| `auth_username` | String | Nullable |
| `auth_secret` | String | Nullable; never exposed in API reads |
| `provider_config` | JSON | e.g. `{"project_key": "SEC", "issue_type": "Bug"}` |
| `webhook_secret` | String | Nullable; HMAC secret for webhook verification |
| `created_at` | DateTime | |
| `updated_at` | DateTime | |

Relationships: `field_mappings` (1:N, cascade), `tickets` (1:N, cascade), `webhook_registrations` (1:N, cascade), `automation_rules` (1:N)

### `IntegrationFieldMapping`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `integration_id` | String FK → integrations | |
| `source` | String | e.g. `finding.severity`, `finding.vulnerability_id` |
| `target_field` | String | e.g. `priority`, `labels`, `custom_field_10001` |
| `transform` | String | Nullable; e.g. `severity_to_priority` |
| `template_value` | String | Nullable; Jinja-like template |
| `priority` | Integer | Mapping evaluation order |

### `Ticket`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `integration_id` | String FK → integrations | |
| `finding_id` | String FK → findings | Nullable; SET NULL on delete |
| `external_id` | String | Jira issue ID |
| `external_key` | String | Jira issue key (e.g. `SEC-123`) |
| `external_url` | String | Full URL to Jira issue |
| `external_status` | String | Nullable; synced from Jira |
| `external_assignee` | String | Nullable; synced from Jira |
| `external_priority` | String | Nullable; synced from Jira |
| `summary` | String | Ticket title |
| `created_at` | DateTime | |
| `synced_at` | DateTime | Nullable; last status sync time |

Unique constraint: `(integration_id, finding_id)` — one ticket per finding per integration.

Relationships: `integration` (N:1), `finding` (N:1), `comments` (1:N, cascade)

### `WebhookEvent`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `integration_id` | String FK → integrations | |
| `event_type` | String | e.g. `jira:issue_updated` |
| `external_issue_id` | String | Nullable |
| `external_issue_key` | String | Nullable |
| `payload` | JSON | Raw webhook payload |
| `status` | Enum | `received`, `processing`, `processed`, `failed`, `ignored` |
| `error_message` | String | Nullable |
| `received_at` | DateTime | |
| `processed_at` | DateTime | Nullable |

### `WebhookRegistration`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `integration_id` | String FK → integrations | Unique (one per integration) |
| `external_webhook_id` | String | Nullable; ID from Jira auto-registration |
| `callback_url` | String | |
| `jira_events` | JSON | List of subscribed events |
| `secret` | String | Nullable; HMAC secret |
| `is_cloud` | Boolean | Default True |
| `created_at` | DateTime | |
| `updated_at` | DateTime | |

### `TicketComment`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `ticket_id` | String FK → tickets | |
| `external_comment_id` | String | Nullable |
| `author` | String | Nullable |
| `body` | Text | |
| `direction` | Enum | `inbound`, `outbound` |
| `created_at` | DateTime | |

### `AutomationRule`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `name` | String | |
| `description` | String | Nullable |
| `enabled` | Boolean | |
| `trigger` | String | e.g. `jira_status_changed`, `scan_completed` |
| `conditions` | JSON | List of condition dicts |
| `actions` | JSON | List of action dicts |
| `integration_id` | String FK → integrations | Nullable; SET NULL on delete |
| `team_id` | String FK → teams | Nullable; SET NULL on delete |
| `execution_count` | Integer | Incremented on each firing |
| `last_executed_at` | DateTime | Nullable |
| `created_at` | DateTime | |
| `updated_at` | DateTime | |

Relationships: `integration` (N:1), `team` (N:1), `executions` (1:N, cascade)

### `AutomationRuleExecution`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `rule_id` | String FK → automation_rules | |
| `trigger_event` | String | |
| `trigger_context` | JSON | |
| `conditions_matched` | Boolean | |
| `actions_executed` | JSON | List of `{action_type, success, detail}` |
| `status` | Enum | `success`, `partial_failure`, `failed`, `skipped` |
| `created_at` | DateTime | |

---

## Ticketing System (`services/ticketing/`)

### Provider Architecture

`TicketingProvider` is an abstract base class (`base.py`) defining the interface:
- `test_connection()` → `TestResult`
- `create_ticket(fields)` → `TicketResult`
- `get_ticket_status(external_id)` → `str | None`
- `add_comment(external_id, body)` → `str | None` (returns comment ID)
- `register_webhook(callback_url, events)` → `dict`
- `deregister_webhook(webhook_id)` → `None`

`get_provider(provider, base_url, auth_method, username, secret, provider_config)` is the factory function in `__init__.py`.

### JiraProvider (`jira_provider.py`)

Implements all provider methods using Jira REST API v3 (Cloud) or v2 (Server):
- Creates issues with configurable project key, issue type, priority, labels
- Supports basic auth and API token auth
- Registers/deregisters webhooks via Jira REST API
- Gets issue status by ID
- Adds comments with Atlassian Document Format (ADF)

### Field Mapper (`field_mapper.py`)

`build_ticket_fields(integration, mappings, finding, scan, overrides)` transforms Finding data into Jira fields:
- Applies `IntegrationFieldMapping` rows in priority order
- Supports transforms: `severity_to_priority` (maps CRITICAL→Highest, HIGH→High, etc.)
- Template values can reference finding/scan attributes
- Manual overrides from API request are applied last

### Webhook Processor (`webhook_processor.py`)

- `parse_jira_event(payload)` → dict with issue_id, issue_key, event_type, status, assignee, priority, comment
- `classify_event_triggers(parsed)` → list of trigger strings (e.g. `["jira_status_changed", "jira_assignee_changed"]`)
- `process_webhook_event(db, event)` → `ProcessResult` (updates matched ticket state)
- `verify_hmac_signature(body, secret, signature)` → bool (HMAC-SHA256)

### Auto-ticket Creation (`auto_tickets.py`)

Called at end of scan pipeline for teams with `auto_create_tickets=True`:
- Filters findings by team's `ticket_severity_threshold`
- Skips findings that already have a ticket for the team's integration
- Creates tickets via the team's linked integration

---

## Automation Engine (`services/automation/engine.py`)

### `evaluate_automation_rules(db, trigger, context)` → `list[AutomationRuleExecution]`

1. Load all enabled rules matching the trigger
2. For each rule, evaluate all conditions against the context
3. If all conditions match: execute each action
4. Persist `AutomationRuleExecution` with results
5. Increment rule's `execution_count`

### Triggers (9)

| Trigger | Source | Context keys |
|---|---|---|
| `jira_status_changed` | Webhook | `integration_id`, `jira_status`, `old_status`, `ticket_id`, `finding_id` |
| `jira_priority_changed` | Webhook | `integration_id`, `new_priority`, `old_priority`, `ticket_id` |
| `jira_comment_added` | Webhook | `integration_id`, `comment_body`, `comment_author`, `ticket_id` |
| `jira_assignee_changed` | Webhook | `integration_id`, `new_assignee`, `old_assignee`, `ticket_id` |
| `jira_issue_deleted` | Webhook | `integration_id`, `external_issue_key`, `ticket_id` |
| `scan_completed` | Scan pipeline | `scan_id`, `scan_type`, `target`, `team_id`, `finding_count` |
| `finding_fixed` | Scan pipeline | `finding_id`, `vulnerability_id`, `package_name`, `severity` |
| `finding_regressed` | Scan pipeline | `finding_id`, `vulnerability_id`, `package_name`, `severity` |
| `policy_violated` | Scan pipeline | `scan_id`, `policy_id`, `policy_name`, `violation_count` |

### Conditions (8)

| Condition type | Field | Description |
|---|---|---|
| `severity_gte` | `min_severity` | Finding severity ≥ threshold |
| `cvss_gte` | `min_score` | Finding CVSS ≥ score |
| `status_equals` | `status` | Jira status equals value |
| `priority_equals` | `priority` | Jira priority equals value |
| `package_matches` | `pattern` | Package name matches glob/regex |
| `ecosystem_equals` | `ecosystem` | Package ecosystem equals value |
| `team_equals` | `team_id` | Scan's team matches |
| `has_fix` | `value` (bool) | Finding has a fix version |

### Actions (6)

| Action type | Fields | Description |
|---|---|---|
| `create_ticket` | `integration_id` | Create a Jira ticket for the finding |
| `add_comment` | `body` | Add a comment to the matched ticket |
| `transition_ticket` | `status` | Transition the Jira ticket to a status |
| `accept_risk` | — | Mark the finding as risk-accepted |
| `send_notification` | `channel`, `message` | Send a notification (extensible) |
| `update_priority` | `priority` | Update the Jira ticket priority |

---

## Pydantic Schemas (`schemas.py`)

### Scan schemas

- **`ScanCreate`** — `scan_type`, `target`, optional `packages`, `registry_id`, `scanner_override`, `team_id`
- **`ScanSummary`** — used by `GET /api/scans` (list). Includes severity counts, duration, team/registry names but **not** `findings[]`.
- **`ScanRead`** — used by `GET /api/scans/{id}` (detail) and `POST /api/scans`. Embeds the full `findings[]` list. Has both `finding_count` and `findings_count` (same value, kept for frontend compatibility). Computes `scan_duration_seconds` via model validator.

### Finding schemas

- **`FindingRead`** — `model_config = {"from_attributes": True}`.

### SBOM schemas

- **`SBOMRead`** — has a `@model_validator(mode="after")` called `extract_components` that flattens `content["components"]` into a typed `components[]` list.
- **`SBOMIngestRequest`** — `name`, `content`, `format`

### Policy schemas

- **`PolicyCreate`**, **`PolicyUpdate`**, **`PolicyRead`**
- **`PolicyResultRead`** — includes `policy_name` and `status` (`"pass"` / `"warn"` / `"fail"`) computed by `_compute_policy_status()`.

### Registry schemas

- **`RegistryCreate`**, **`RegistryUpdate`**, **`RegistryRead`**, **`RegistryTestResult`**

### Team schemas

- **`TeamCreate`**, **`TeamUpdate`**, **`TeamRead`** (includes `ownership_rules`, `scan_count`, `integration_name`)
- **`OwnershipRuleCreate`**, **`OwnershipRuleRead`**
- **`TeamFindingSummary`** — includes SLA context (hours_elapsed, sla_violated)
- **`TeamDashboardReport`** — team stats + findings list

### Integration schemas

- **`IntegrationCreate`**, **`IntegrationUpdate`**, **`IntegrationRead`** (includes `has_secret`, `field_mappings`)
- **`IntegrationFieldMappingCreate`**, **`IntegrationFieldMappingRead`**
- **`CreateTicketRequest`**, **`BulkCreateTicketsRequest`**, **`BulkCreateTicketsResponse`**
- **`TicketRead`**, **`TestIntegrationResponse`**

### Webhook schemas

- **`WebhookEventRead`**, **`WebhookEventDetail`** (extends with full payload)
- **`WebhookRegistrationCreate`**, **`WebhookRegistrationRead`**

### Ticket Comment schemas

- **`TicketCommentCreate`**, **`TicketCommentRead`**

### Automation schemas

- **`AutomationRuleCreate`**, **`AutomationRuleUpdate`**, **`AutomationRuleRead`**
- **`AutomationRuleExecutionRead`**

### Other schemas

- **`DashboardReport`**, **`SeverityTrendPoint`**, **`TopVulnerability`**
- **`AuditLogRead`**, **`SettingRead`**, **`SettingUpdate`**

---

## Repository Pattern (`repositories/`)

### `BaseRepository[T]` (`base.py`)

All DB access goes through these methods:

| Method | Description |
|---|---|
| `get(pk)` | `db.get(model, pk)` — returns `None` if missing |
| `get_or_404(pk, detail)` | Raises `HTTPException(404)` if missing |
| `list(skip, limit, order_by, filters)` | Filterable, orderable query |
| `count(filters)` | `COUNT(id)` with optional filters |
| `add(obj)` | `db.add(obj)` — no commit |
| `add_all(objs)` | Bulk add — no commit |
| `flush()` | `db.flush()` — write without commit |
| `commit()` | `db.commit()` |
| `refresh(obj)` | `db.refresh(obj)` |
| `delete(obj)` | `db.delete(obj)` + `db.commit()` |
| `save(obj)` | `add` + `commit` + `refresh` in one call |

### Concrete repositories (`repos.py`) — 20 classes

| Repository | Extra methods |
|---|---|
| `ScanRepository` | `list_with_filters(skip, limit, scan_type, status)`, `delete_all()` |
| `FindingRepository` | `for_scan(scan_id, severity, is_fixed)` ordered by `risk_score DESC`; `severity_counts()`; `top_vulnerabilities(limit)`; `trend_since(days)` |
| `PolicyRepository` | `list_enabled()`, `list_all()` ordered by `created_at DESC` |
| `PolicyResultRepository` | `for_scan(scan_id)` |
| `SBOMRepository` | `for_scan(scan_id)` returns first or `None` |
| `AuditLogRepository` | `list_with_filters(skip, limit, action, resource_type)` ordered by `created_at DESC` |
| `SettingRepository` | `get_value(key, default)`, `set_value(key, value)`, `ensure_defaults(dict)` |
| `RegistryRepository` | `list_all()`, `list_auto_sync()`, `get_by_name(name)`, `update_cache(registry_id, cache, synced_at)` |
| `TeamRepository` | `list_all()`, `get_by_name(name)`, `scans_for_team(team_id, limit)` |
| `OwnershipRuleRepository` | `list_all()`, `for_team(team_id)` |
| `VulnerabilityInstanceRepository` | `find_by_key(vuln_id, pkg, target)`, `upsert(...)`, `severity_counts(team_id)`, `total_count(team_id)`, `top_vulnerabilities(limit, team_id)`, `trend_since(days, team_id)`, `for_team(team_id)` |
| `IntegrationRepository` | `list_all()`, `list_enabled(provider)` |
| `IntegrationFieldMappingRepository` | `for_integration(integration_id)`, `replace_for_integration(integration_id, mappings)` |
| `TicketRepository` | `for_integration(integration_id, limit)`, `for_finding(finding_id)`, `exists_for_integration_and_finding(...)`, `bulk_check_existing(integration_id, finding_ids)` |
| `WebhookEventRepository` | `list_for_integration(integration_id, skip, limit, status)`, `pending_events(limit)` |
| `WebhookRegistrationRepository` | `for_integration(integration_id)` |
| `TicketCommentRepository` | `for_ticket(ticket_id)` |
| `AutomationRuleRepository` | `list_all()`, `list_enabled(trigger)`, `for_integration(integration_id)`, `increment_execution(rule_id)` |
| `AutomationRuleExecutionRepository` | `for_rule(rule_id, limit)`, `recent(limit)` |

`get_or_404` is used consistently in all routers instead of manual `None` checks.

---

## Policy Evaluation (`services/policy.py`)

`evaluate_policy(policy, findings)` iterates over `policy.rules` and evaluates each:

| Rule type | Key fields | Violation condition |
|---|---|---|
| `severity_threshold` | `min_severity` | Any finding with severity ≥ threshold |
| `cvss_threshold` | `min_score` (float) | Any finding with `cvss_score >= min_score` |
| `fix_available` | `require_fix` (bool) | Any finding where `is_fixed == False` (when `require_fix=True`) |
| `package_blocklist` | `packages` (list of names) | Any finding whose `package_name` (lowercased) is in the list |

Severity ordering: `CRITICAL=4 > HIGH=3 > MEDIUM=2 > LOW=1 > UNKNOWN=0`.

Returns a `PolicyResult` ORM object. Caller must set `scan_id` before persisting.

---

## SBOM Service (`services/sbom.py`)

### `generate_sbom(scan, findings)` → CycloneDX 1.4 dict

- Deduplicates components by `"{ecosystem}/{name}@{version}"` key
- Each component gets a `bom-ref` UUID, `purl` (mapped via `_purl()`), `ecosystem`
- Each finding becomes a `vulnerabilities[]` entry with ratings and `affects` refs
- `bomFormat: "CycloneDX"`, `specVersion: "1.4"`, `serialNumber: "urn:uuid:..."`, `version: 1`
- Tools metadata: `"Dunedain Security Platform" v1.0.0

### `parse_sbom(content)` → package list for OSV scanning

- Auto-detects CycloneDX (by `bomFormat` or presence of `components`) vs SPDX (by `spdxVersion` or `packages`)
- CycloneDX: reads `components[].name` + `.version` + `.purl` (ecosystem derived from purl type)
- SPDX: reads `packages[].name` + `.versionInfo` + `externalRefs[].referenceLocator` (purl)

---

## File Cache (`services/cache.py`)

- **Location:** `$DUNEDAIN_CACHE_DIR/dunedain-cache/` (default: `$TMPDIR/dunedain-cache/`). In Docker Compose this is `/data/cache/dunedain-cache/` on the shared volume.
- **Key:** `SHA-256(scan_type + ":" + target)` — hex digest used as filename
- **TTL:** `$DUNEDAIN_CACHE_TTL` seconds (default: 3600 = 1 hour)
- **Format:** `{"_cached_at": <unix timestamp>, "payload": <raw findings list>}`
- Cache is best-effort: `OSError` on write is silently ignored
- `force=True` on `run_scan` skips the cache lookup entirely

---

## API Routes

All routes are prefixed with `/api` in production. The health endpoint is at `/health`.

### Scans (`/api/scans`)

| Method | Path | Status | Description |
|---|---|---|---|
| POST | `/api/scans` | 202 | Create scan, dispatch Celery task. Body: `ScanCreate`. Returns `ScanRead`. |
| GET | `/api/scans` | 200 | List scans. Query params: `skip`, `limit`, `scan_type`, `status`. Returns `list[ScanSummary]`. |
| GET | `/api/scans/{id}` | 200 | Scan detail with embedded findings. Returns `ScanRead`. |
| GET | `/api/scans/{id}/findings` | 200 | Findings for a scan. Query params: `severity`, `is_fixed`. Returns `list[FindingRead]`. |
| GET | `/api/scans/{id}/sbom` | 200 | SBOM for a scan. Returns `SBOMRead`. 404 if no SBOM. |
| GET | `/api/scans/{id}/policy-results` | 200 | Policy results for a scan with computed `status`. Returns `list[PolicyResultRead]`. |
| POST | `/api/scans/{id}/rerun` | 202 | Create new scan repeating same target/type; dispatches with `force=True`. Returns new `ScanRead`. |
| DELETE | `/api/scans/{id}` | 204 | Delete scan and all cascaded data (findings, SBOM, policy results). |

### Policies (`/api/policies`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/policies` | 200 | List all policies ordered by `created_at DESC`. |
| POST | `/api/policies` | 200 | Create policy. Writes `policy_created` audit log. |
| GET | `/api/policies/{id}` | 200 | Get policy by ID. |
| PUT | `/api/policies/{id}` | 200 | Update policy (full replacement). |
| DELETE | `/api/policies/{id}` | 204 | Delete policy (cascades to policy_results). |
| POST | `/api/policies/{policy_id}/evaluate/{scan_id}` | 200 | On-demand policy evaluation against a scan. Persists new `PolicyResult`. |

### Reports (`/api/reports`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/reports/dashboard` | 200 | Aggregate stats, top 10 vulnerabilities, severity trend (last 30 days), last 10 scans. Returns `DashboardReport`. |
| GET | `/api/reports/audit-log` | 200 | Paginated audit log. Query params: `skip`, `limit` (max 200), `action`, `resource_type`. Returns `list[AuditLogRead]`. |

### SBOM (`/api/sbom`)

| Method | Path | Status | Description |
|---|---|---|---|
| POST | `/api/sbom/ingest` | 200 | Ingest an existing SBOM. Extracts packages, scans with OSV (synchronously), persists scan + findings + SBOM. Writes `sbom_ingested` audit log. |
| GET | `/api/sbom/{id}` | 200 | Get SBOM by its own ID (not scan ID). Returns `SBOMRead`. |

### Vulnerabilities (`/api/vulns`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/vulns/{vuln_id}` | 200 | Proxy to `https://api.osv.dev/v1/vulns/{vuln_id}`. Returns raw OSV JSON. Accepts any OSV ID format. 503 if OSV unreachable, 404 if not found. |

### Settings (`/api/settings`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/settings` | 200 | List all settings (seeds defaults if missing). Returns `list[SettingRead]`. |
| GET | `/api/settings/{key}` | 200 | Get setting by key. 404 if key unknown. |
| PUT | `/api/settings/{key}` | 200 | Update setting value. 400 if key not in `_KNOWN_SETTINGS`. |

### Registries (`/api/registries`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/registries` | 200 | List all registries. |
| POST | `/api/registries` | 201 | Create a registry. |
| GET | `/api/registries/{id}` | 200 | Get registry by ID. |
| PUT | `/api/registries/{id}` | 200 | Update registry. |
| DELETE | `/api/registries/{id}` | 204 | Delete registry. |
| POST | `/api/registries/{id}/sync` | 200 | Trigger async registry sync. |
| POST | `/api/registries/{id}/test` | 200 | Test registry connectivity. |
| GET | `/api/registries/{id}/repos` | 200 | List cached repositories and tags. |

### Teams (`/api/teams`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/teams` | 200 | List all teams. |
| POST | `/api/teams` | 201 | Create a team. |
| GET | `/api/teams/{id}` | 200 | Get team by ID (includes ownership rules). |
| PUT | `/api/teams/{id}` | 200 | Update team. |
| DELETE | `/api/teams/{id}` | 204 | Delete team. |
| POST | `/api/teams/{id}/rules` | 201 | Add ownership rule to team. |
| DELETE | `/api/teams/{id}/rules/{rule_id}` | 204 | Delete ownership rule. |
| GET | `/api/teams/{id}/dashboard` | 200 | Team dashboard with findings and SLA data. Returns `TeamDashboardReport`. |

### Integrations (`/api/integrations`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/integrations` | 200 | List all integrations. |
| POST | `/api/integrations` | 201 | Create integration. Writes `integration_created` audit log. |
| GET | `/api/integrations/{id}` | 200 | Get integration by ID (includes field mappings). |
| PUT | `/api/integrations/{id}` | 200 | Update integration (partial update). |
| DELETE | `/api/integrations/{id}` | 204 | Delete integration (cascades to tickets, mappings, webhooks). |
| POST | `/api/integrations/{id}/test` | 200 | Test integration connectivity. Returns projects list. |
| GET | `/api/integrations/{id}/tickets` | 200 | List tickets for integration. |
| POST | `/api/integrations/tickets` | 201 | Create a single ticket for a finding. |
| POST | `/api/integrations/tickets/bulk` | 200 | Bulk create tickets for multiple findings. |
| GET | `/api/integrations/findings/{finding_id}/tickets` | 200 | List tickets for a finding. |
| POST | `/api/integrations/{id}/sync-status` | 200 | Sync ticket statuses from Jira. |
| POST | `/api/integrations/{id}/webhooks` | 201 | Register webhook for integration (optionally auto-registers with Jira). |
| GET | `/api/integrations/{id}/webhooks` | 200 | Get webhook registration for integration. |
| DELETE | `/api/integrations/{id}/webhooks` | 204 | Delete webhook registration (optionally deregisters from Jira). |
| GET | `/api/integrations/tickets/{ticket_id}/comments` | 200 | List comments for a ticket. |
| POST | `/api/integrations/tickets/{ticket_id}/comments` | 201 | Add outbound comment (syncs to Jira). |

### Webhooks (`/api/webhooks`)

| Method | Path | Status | Description |
|---|---|---|---|
| POST | `/api/webhooks/jira/{integration_id}` | 202 | Receive Jira webhook. Validates integration, verifies HMAC, persists event, dispatches async task. |
| GET | `/api/webhooks/events` | 200 | List webhook events. Query params: `integration_id`, `status`, `skip`, `limit`. |
| GET | `/api/webhooks/events/{event_id}` | 200 | Get webhook event with full payload. |
| POST | `/api/webhooks/events/{event_id}/retry` | 202 | Retry a failed/ignored webhook event. |

### Automation (`/api/automation`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/automation/triggers` | 200 | List valid trigger names. |
| GET | `/api/automation/rules` | 200 | List automation rules. Query params: `trigger`, `enabled`, `integration_id`. |
| POST | `/api/automation/rules` | 201 | Create automation rule. Validates trigger name. Writes audit log. |
| GET | `/api/automation/rules/{rule_id}` | 200 | Get automation rule by ID. |
| PUT | `/api/automation/rules/{rule_id}` | 200 | Update automation rule. |
| DELETE | `/api/automation/rules/{rule_id}` | 204 | Delete automation rule (cascades to executions). |
| POST | `/api/automation/rules/{rule_id}/toggle` | 200 | Toggle rule enabled state. |
| GET | `/api/automation/rules/{rule_id}/executions` | 200 | List execution history for a rule. |
| GET | `/api/automation/executions/recent` | 200 | List recent executions across all rules. |

### Health

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/health` | 200 | `{"status": "ok", "version": "1.0.0"}` |

---

## Startup Behaviour (`main.py`)

On application startup (FastAPI lifespan):

1. `Base.metadata.create_all(bind=engine)` — creates all tables if they don't exist
2. `_run_alembic_upgrade()` — applies pending Alembic migrations (skips if `alembic.ini` absent)
3. `_seed_default_policies()` — if the `policies` table is empty, inserts 4 default policies:
   - **Block Critical Vulnerabilities** — `severity_threshold` CRITICAL, action `block`
   - **Warn on High Vulnerabilities** — `severity_threshold` HIGH, action `warn`
   - **Require Fix Available** — `fix_available`, action `warn`
   - **CVE Score Threshold** — `cvss_threshold` min_score=9.0, action `block`

### CORS

The `ALLOWED_ORIGINS` environment variable controls allowed origins (comma-separated list or `*`). `allow_credentials` is set to `True` only when origins are explicit (not `*`).

---

## Frontend Architecture

### Routing (`App.tsx`)

All routes are nested under the `<Layout>` component using React Router v6:

| Path | Page component |
|---|---|
| `/dashboard` | `Dashboard` |
| `/scans` | `Scans` |
| `/scans/:id` | `ScanDetail` |
| `/policies` | `Policies` |
| `/sbom/:scanId` | `SBOMViewer` |
| `/audit-log` | `AuditLog` |
| `/settings` | `Settings` |
| `/workers` | `Workers` |
| `/registries` | `Registries` |
| `/teams` | `Teams` |
| `/teams/:teamId/dashboard` | `TeamDashboard` |
| `/integrations` | `Integrations` |
| `/automation` | `AutomationRules` |
| `/seed` | `SeedScans` |
| `/` | Redirects to `/dashboard` |

### React Query configuration

- `retry: 1`, `refetchOnWindowFocus: false` globally
- **Scans list** (`Scans.tsx`): polls every **3 seconds** when any scan has `status: "pending"` or `"running"`
- **Scan detail** (`ScanDetail.tsx`): polls every **2 seconds** while the scan is active
- **Workers page** (`Workers.tsx`): polls every **1.5 seconds** unconditionally
- **OSV detail** (`FindingCard.tsx`): `staleTime: 5 minutes` (cached aggressively)

### TypeScript types (`types.ts`)

~25 interfaces including: `Scan`, `Finding`, `Policy`, `PolicyRule`, `DashboardData`, `SBOMComponent`, `SBOM`, `PolicyResult`, `AuditLogEntry`, `OsvVulnerability`, `OsvAffectedPackage`, `Registry`, `Team`, `OwnershipRule`, `TeamFindingSummary`, `TeamDashboardData`, `Integration`, `IntegrationFieldMapping`, `Ticket`, `BulkCreateTicketsResponse`, `WebhookEvent`, `WebhookEventDetail`, `WebhookRegistration`, `TicketComment`, `AutomationRule`, `AutomationRuleExecution`.

---

## Frontend Pages

### `Dashboard.tsx`

- 4 stat cards: Total Scans, Total Findings, Critical, High
- Recharts `BarChart` with per-severity colored bars
- Top vulnerabilities table (up to 8 rows)
- Recent scans table (last 10 from API)

### `Scans.tsx`

- Filterable by `scan_type` and `status`
- New Scan modal: type selector, target input, optional packages JSON (for dependency scans)
- Per-row: severity counts (C/H/M/L), rerun button (`RotateCcw`), delete button (`Trash2`)
- Delete confirmation modal warns about cascaded data removal

### `ScanDetail.tsx`

Three tabs: **Findings**, **SBOM**, **Policy Results**

- **Findings tab**: search by vuln ID or package name; severity filter buttons; "Group by CVE" toggle
- **SBOM tab**: lazy-loaded on tab click; shows component table
- **Policy Results tab**: lazy-loaded on tab click; shows pass/warn/fail badge and violations list
- Header: shows `base_image` + `base_image_chain` for container scans; scanner engine badge; rerun button

### `Policies.tsx`

Full CRUD with `PolicyRuleEditor` component for adding/editing rules.

### `SBOMViewer.tsx`

Standalone page for viewing the SBOM of a scan by `scanId` URL param.

### `Settings.tsx`

Renders all settings from `GET /api/settings`. Currently only `scanner_backend` is configurable.

### `Workers.tsx`

Rack-unit visualisation with 3 `ServerUnit` components, each with 8 `Slot` components. LED colors indicate scanner engine. Animations for active slots.

### `AuditLog.tsx`

Filterable by `action` and `resource_type`; paginated.

### `Registries.tsx`

Registry CRUD with repository browsing, auto-sync/auto-scan controls, connectivity testing.

### `SeedScans.tsx`

Synthetic scan generation for development/demo purposes with progress orchestration.

### `Teams.tsx`

Team CRUD with inline ownership rule editor, auto-ticket configuration (integration picker, severity threshold).

### `TeamDashboard.tsx`

Team-specific view showing unique vulnerability findings with SLA tracking, severity breakdown, and links to original scans.

### `Integrations.tsx` (~900 lines)

Full integration management:
- Integration CRUD with provider picker (Jira), auth configuration
- Field mapping editor (FieldMappingEditor component)
- Ticket list with status sync
- Bulk ticket creation
- Webhook registration management
- Ticket comment thread

### `AutomationRules.tsx` (~500 lines)

Automation rule management:
- Rule table with enable/disable toggle
- Create/edit modal with AutomationRuleEditor component
- Execution history per rule

---

## Key Components

### `FindingCard.tsx`

- Collapsible row showing: vuln ID, package@version, severity badge, CVSS, fix availability
- Expanded view: description, fix version, risk score, ecosystem, exploitable flag, aliases, top 3 references
- **"View Full OSV Details"** toggle opens `OsvDetailPanel` (inline, lazy-fetched)

### `OsvDetailPanel` (inside `FindingCard.tsx`)

- Calls `GET /api/vulns/{vuln_id}` (backend proxy to OSV)
- Displays: published/modified dates, CWE IDs, full description, CVSS vectors, affected ranges, references

### `PolicyRuleEditor.tsx`

- Supports all 4 rule types with appropriate inputs

### `FieldMappingEditor.tsx`

- Source picker (finding/scan attributes), target field input, transform selector, template value
- Add/remove mapping rows with priority ordering

### `AutomationRuleEditor.tsx` (~630 lines)

- Trigger picker (dropdown of 9 valid triggers)
- Condition builder: add conditions with type-specific inputs
- Action builder: add actions with type-specific inputs
- Integration and team selectors (optional)

---

## CI/CD Workflows

### `ci.yml`

Triggers: push to `main`/`develop`, PRs to `main`

1. `backend-test`: pytest with Python 3.12
2. `frontend-build`: `npm ci && npm run build` with Node 20

---

## Coding Conventions

### Backend (Python)

- Follow **PEP 8**.
- Use **Pydantic v2** models for all request/response schemas (in `schemas.py`).
- Use **SQLAlchemy ORM** models (in `models.py`); never write raw SQL or use `text()`.
- Route handlers go in `app/routers/`; business logic goes in `app/services/`.
- All DB access goes through the repository layer (`app/repositories/`); do not call `db.query()` directly in routers.
- Use `repo.get_or_404(pk, detail="...")` instead of manual `None` checks + `HTTPException`.
- Use `httpx` (not `requests`) for outbound HTTP; the OSV proxy route uses async `httpx.AsyncClient`.
- Keep all API endpoints under the `/api/` prefix.
- Write tests using `pytest`; place them in `backend/tests/`.
- New audit-worthy actions should write an `AuditLog` row with a descriptive `action` string.
- Schema changes require a new Alembic migration in `backend/migrations/versions/`.
- New ticketing providers should implement the `TicketingProvider` ABC and register in `services/ticketing/__init__.py`.

### Frontend (TypeScript/React)

- **Functional components** with React hooks only; no class components.
- Shared TypeScript interfaces live in `src/types.ts`; always use them, never inline `any` types in props.
- API calls go through typed functions in `src/api/`; use **TanStack Query** (`useQuery`, `useMutation`) for all data fetching and cache invalidation.
- UI components go in `src/components/`, full pages in `src/pages/`.
- Use the existing **CSS custom properties** (`--bg-card`, `--bg-primary`, `--bg-secondary`, `--border`, `--accent`, `--text-primary`, `--text-secondary`, `--critical`, `--high`, `--medium`, `--low`, `--success`, `--warning`, `--error`) — do not add a new CSS framework or reset the dark theme.
- Use inline styles with the CSS variable references; the project does not use CSS Modules or Tailwind.
- When adding a new scan-related polling query, use the `refetchInterval` callback pattern — return an interval in ms only while scans are active, otherwise `false`.

---

## Database & Migrations

### Database Configuration (`database.py`)

- `DATABASE_URL` env var controls the database. Default: `sqlite:///./dunedain.db`
- Docker Compose uses PostgreSQL (configured in `docker-compose.yml`)
- `check_same_thread=False` only applied for SQLite connections
- Connection pool: `pool_size=20`, `max_overflow=40`, `pool_timeout=60`

### Alembic Migrations

- 7 migrations in `backend/migrations/versions/`
- `render_as_batch=True` in `env.py` for SQLite DDL compatibility (safe for PostgreSQL)
- `main.py` runs `alembic upgrade head` on startup after `create_all()`
- All migrations guard column/table operations with existence checks (idempotent with `create_all`)
- Skips silently when `alembic.ini` is absent (e.g. test environments)

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./dunedain.db` | SQLAlchemy connection string |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery broker |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Celery result backend |
| `DUNEDAIN_CACHE_DIR` | `$TMPDIR` | Directory for file-based scan result cache |
| `DUNEDAIN_CACHE_TTL` | `3600` | Cache TTL in seconds |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins or `*` |
