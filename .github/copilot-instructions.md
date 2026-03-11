# Copilot Instructions

## Project Overview

**dunedain** is an open-source, self-hostable software supply chain security platform. It scans containers, source directories, and dependency manifests for known vulnerabilities using Trivy, Grype, and the [osv.dev](https://osv.dev) API. It enforces configurable security policies, generates CycloneDX SBOMs, and provides a real-time dashboard for prioritizing and remediating findings.

---

## Repository Structure

```
.
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app entry point, lifespan, CORS, router registration, default policy seeding
│   │   ├── models.py            # SQLAlchemy ORM models (7 models)
│   │   ├── schemas.py           # Pydantic v2 request/response schemas
│   │   ├── database.py          # SQLAlchemy engine + SessionLocal (SQLite by default)
│   │   ├── celery_app.py        # Celery application + configuration
│   │   ├── routers/
│   │   │   ├── scans.py         # Scan CRUD + findings/sbom/policy-results sub-resources
│   │   │   ├── policies.py      # Policy CRUD + on-demand evaluate endpoint
│   │   │   ├── reports.py       # Dashboard stats + audit log
│   │   │   ├── sbom.py          # SBOM ingest + get-by-id
│   │   │   ├── settings.py      # App settings key-value store
│   │   │   └── vulns.py         # OSV.dev proxy (deep-dive)
│   │   ├── repositories/
│   │   │   ├── base.py          # BaseRepository[T] generic CRUD
│   │   │   └── repos.py         # 7 concrete repository classes
│   │   ├── services/
│   │   │   ├── scanner.py       # All scanner logic (Trivy, Grype, OSV, manifest parsing)
│   │   │   ├── policy.py        # Policy rule evaluation
│   │   │   ├── risk.py          # Risk score computation + finding prioritization
│   │   │   ├── sbom.py          # CycloneDX SBOM generation + SBOM parsing (CycloneDX/SPDX)
│   │   │   └── cache.py         # File-based scan result cache
│   │   └── tasks/
│   │       └── scan.py          # Celery task: run_scan (full 8-step pipeline)
│   ├── tests/
│   │   ├── test_api.py
│   │   └── test_services.py
│   ├── Dockerfile               # Includes Trivy v0.69.3 + Grype v0.109.0 baked in
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.tsx              # Router setup, QueryClient config
│   │   ├── types.ts             # All shared TypeScript interfaces
│   │   ├── api/                 # Axios client functions (one file per domain)
│   │   ├── components/
│   │   │   ├── Layout.tsx
│   │   │   ├── FindingCard.tsx  # Collapsible card with inline OsvDetailPanel
│   │   │   ├── PolicyRuleEditor.tsx
│   │   │   ├── StatusBadge.tsx
│   │   │   └── SeverityBadge.tsx
│   │   └── pages/
│   │       ├── Dashboard.tsx    # Stats + bar chart + top vulns + recent scans
│   │       ├── Scans.tsx        # Scan list with create/delete/rerun modals
│   │       ├── ScanDetail.tsx   # 3-tab detail (Findings / SBOM / Policy Results)
│   │       ├── Policies.tsx     # Policy CRUD with PolicyRuleEditor
│   │       ├── SBOMViewer.tsx   # Standalone SBOM component table
│   │       ├── Settings.tsx     # scanner_backend toggle
│   │       ├── Workers.tsx      # Rack-unit visualisation of 3 workers × 8 slots
│   │       └── AuditLog.tsx     # Filterable audit event log
│   ├── Dockerfile               # nginx-based static host
│   └── package.json
├── docs/
│   └── database-portability.md  # PostgreSQL migration guide + 4 known blockers
├── docker-compose.yml
└── .github/workflows/
    └── ci.yml
```

---

## Tech Stack

| Layer | Technologies |
|---|---|
| **Backend** | Python 3.12, FastAPI, SQLAlchemy (ORM only, no raw SQL), SQLite (default), Pydantic v2, httpx, Celery, Redis |
| **Frontend** | React 19, TypeScript, Vite, @tanstack/react-query v5, Axios, Recharts, React Router v6, Lucide icons |
| **Scanner engines** | Trivy v0.69.3 (baked into Docker image), Grype v0.109.0 (baked into Docker image), osv.dev batch API |
| **SBOM** | CycloneDX 1.4 JSON (generated); also parses SPDX JSON on ingest |
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

### CLI scanner

The `scripts/` directory and its `scan_dependencies.py` CLI tool were removed during the async pipeline refactor. Dependency scanning is now handled entirely by the backend scanner engine (Trivy + Grype + OSV) running inside Celery workers.

---

## Async Architecture: Celery + Redis

All scan execution is **asynchronous**. The FastAPI backend creates a `Scan` row with `status="pending"` and immediately returns `202 Accepted`. The actual scan runs in a Celery worker.

### Configuration (`celery_app.py`)

- **Broker / backend:** Redis — env vars `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` (default: `redis://localhost:6379/0`)
- `task_acks_late=True` — task acknowledged only after completion (safe against worker crash)
- `worker_prefetch_multiplier=1` — one task at a time per worker process
- Soft time limit: 29 min (SIGTERM); hard limit: 30 min (SIGKILL)
- Queue name: `scans`

### Docker Compose scaling

```yaml
worker:
  command: celery -A app.celery_app worker --loglevel=info --concurrency=8 -Q scans
  deploy:
    replicas: 3
```

3 worker containers × 8 concurrent tasks = 24 maximum parallel scans. Workers and the backend **share** the `dunedain-data` Docker volume (SQLite database + file cache).

### The `run_scan` Celery task (`tasks/scan.py`)

The pipeline runs in this exact order:

1. Set `scan.status = "running"`, commit
2. Compute cache key (`SHA-256` of `"scan_type:target"`); check file cache (skip if `force=True`)
3. If cache miss: dispatch to the appropriate scanner function (`scan_dependencies`, `scan_container`, or `scan_source`)
4. Write raw findings to cache (`set_cache`)
5. Persist `Finding` rows, `db.flush()`
6. Call `prioritize_findings` — sorts findings by `risk_score` descending in memory
7. Evaluate all enabled `Policy` rows; persist `PolicyResult` rows
8. Generate CycloneDX SBOM; persist `SBOM` row
9. Set `scan.status = "completed"`, set `scanner_engine`, `base_image`, `base_image_chain`, `completed_at`, commit
10. Write `AuditLog` entry with action `"scan_completed"`

On any unhandled exception the task sets `scan.status = "failed"` and re-raises.

---

## Scanner Engine System (`services/scanner.py`)

### Scanner selection

The `scanner_backend` app setting controls which engine is used:

| Value | Behaviour |
|---|---|
| `auto` (default) | Try Trivy, then Grype, then OSV-only |
| `trivy` | Use Trivy + OSV enrichment only |
| `grype` | Use Grype + OSV enrichment only |

The preference is read from the `AppSetting` table via `_get_scanner_preference()` at scan time.

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

Primary scanner findings come first; OSV-enrichment findings are appended only if `(vulnerability_id, package_name)` is not already present.

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

All primary keys are UUIDs stored as `String`. All `DateTime` columns store UTC.

### `Scan`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `name` | String | |
| `scan_type` | Enum | `container`, `dependency`, `source` |
| `target` | String | Image name, path, or package target |
| `status` | Enum | `pending`, `running`, `completed`, `failed` |
| `created_at` | DateTime | |
| `completed_at` | DateTime | Nullable |
| `cached` | Boolean | True if results served from file cache |
| `scanner_engine` | String | `trivy`, `grype`, or `osv`; nullable |
| `base_image` | String | Container scans only; nullable |
| `base_image_chain` | JSON | List of layer ancestry names; nullable |
| `packages` | JSON | Stored for dependency reruns; nullable |

Relationships: `findings` (1:N, `cascade="all, delete-orphan"`), `sbom` (1:1, `cascade="all, delete-orphan"`), `policy_results` (1:N, `cascade="all, delete-orphan"`)

### `Finding`

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | |
| `scan_id` | String FK → scans | |
| `package_name` | String | |
| `package_version` | String | |
| `package_ecosystem` | String | |
| `vulnerability_id` | String | e.g. `CVE-2023-1234`, `GHSA-...` |
| `severity` | Enum | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` |
| `cvss_score` | Float | Nullable |
| `description` | Text | Truncated to 500 chars from scanner output |
| `fix_version` | String | Nullable |
| `is_fixed` | Boolean | |
| `reachable` | Boolean | |
| `exploitable` | Boolean | |
| `risk_score` | Float | |
| `aliases` | JSON | List of alternate IDs |
| `references` | JSON | List of URLs |

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
| `action` | String | `scan_completed`, `policy_created`, `sbom_ingested` |
| `resource_type` | String | `scan`, `policy`, `sbom` |
| `resource_id` | String | Nullable |
| `details` | JSON | |
| `created_at` | DateTime | |

### `AppSetting`

| Column | Type | Notes |
|---|---|---|
| `key` | String PK | |
| `value` | String | |
| `description` | String | Nullable |
| `updated_at` | DateTime | |

Currently defined key: `scanner_backend` (default: `"auto"`).

---

## Pydantic Schemas (`schemas.py`)

### Schema variants

- **`ScanSummary`** — used by `GET /api/scans` (list). Includes severity counts but **not** `findings[]`.
- **`ScanRead`** — used by `GET /api/scans/{id}` (detail) and `POST /api/scans`. Embeds the full `findings[]` list. Has both `finding_count` and `findings_count` (same value, kept for frontend compatibility).
- **`FindingRead`** — `model_config = {"from_attributes": True}`.
- **`SBOMRead`** — has a `@model_validator(mode="after")` called `extract_components` that flattens `content["components"]` into a typed `components[]` list with keys `name`, `version`, `purl`, `ecosystem`, `licenses`. This runs automatically on serialization.
- **`PolicyResultRead`** — includes `policy_name` (joined from Policy) and `status` (`"pass"` / `"warn"` / `"fail"`) computed by `_compute_policy_status()`.

### `_compute_policy_status(passed, policy_action)` helper

```python
if passed:           return "pass"
if action in ("warn", "audit"): return "warn"
return "fail"        # action == "block" and not passed
```

### Other schemas

`PolicyCreate`, `PolicyUpdate`, `PolicyRead`, `SBOMIngestRequest`, `DashboardReport`, `SeverityTrendPoint`, `TopVulnerability`, `AuditLogRead`, `SettingRead`, `SettingUpdate`.

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

### Concrete repositories (`repos.py`)

| Repository | Extra methods |
|---|---|
| `ScanRepository` | `list_with_filters(skip, limit, scan_type, status)` |
| `FindingRepository` | `for_scan(scan_id, severity, is_fixed)` ordered by `risk_score DESC`; `severity_counts()`; `top_vulnerabilities(limit)`; `trend_since(days)` |
| `PolicyRepository` | `list_enabled()`, `list_all()` ordered by `created_at DESC` |
| `PolicyResultRepository` | `for_scan(scan_id)` |
| `SBOMRepository` | `for_scan(scan_id)` returns first or `None` |
| `AuditLogRepository` | `list_with_filters(skip, limit, action, resource_type)` ordered by `created_at DESC` |
| `SettingRepository` | `get_value(key, default)`, `set_value(key, value)`, `ensure_defaults(dict)` |

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
- Tools metadata: `"Dunedain Security Platform" v1.0.0`

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
| GET | `/api/vulns/{vuln_id}` | 200 | Proxy to `https://api.osv.dev/v1/vulns/{vuln_id}`. Returns raw OSV JSON. Accepts any OSV ID format (`CVE-*`, `GHSA-*`, `PYSEC-*`, `RUSTSEC-*`, etc.). 503 if OSV unreachable, 404 if not found. |

### Settings (`/api/settings`)

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/api/settings` | 200 | List all settings (seeds defaults if missing). Returns `list[SettingRead]`. |
| GET | `/api/settings/{key}` | 200 | Get setting by key. 404 if key unknown. |
| PUT | `/api/settings/{key}` | 200 | Update setting value. 400 if key not in `_KNOWN_SETTINGS`. |

### Health

| Method | Path | Status | Description |
|---|---|---|---|
| GET | `/health` | 200 | `{"status": "ok", "version": "1.0.0"}` |

---

## Startup Behaviour (`main.py`)

On application startup (FastAPI lifespan):

1. `Base.metadata.create_all(bind=engine)` — creates all tables if they don't exist
2. `_seed_default_policies()` — if the `policies` table is empty, inserts 4 default policies:
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
| `/` | Redirects to `/dashboard` |

### React Query configuration

- `retry: 1`, `refetchOnWindowFocus: false` globally
- **Scans list** (`Scans.tsx`): polls every **3 seconds** when any scan has `status: "pending"` or `"running"`
- **Scan detail** (`ScanDetail.tsx`): polls every **2 seconds** while the scan is active
- **Workers page** (`Workers.tsx`): polls every **1.5 seconds** unconditionally
- **OSV detail** (`FindingCard.tsx`): `staleTime: 5 minutes` (cached aggressively)

### TypeScript types (`types.ts`)

Key interfaces: `Scan`, `Finding`, `Policy`, `PolicyRule`, `DashboardData`, `SBOMComponent`, `SBOM`, `PolicyResult`, `AuditLogEntry`, `OsvVulnerability`, `OsvAffectedPackage`.

`PolicyRule.type` is a discriminated union: `'severity_threshold' | 'cvss_threshold' | 'fix_available' | 'package_blocklist'`.

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

- **Findings tab**: search by vuln ID or package name; severity filter buttons; "Group by CVE" toggle (collapses findings under a `CveGroup` accordion per vulnerability ID)
- **SBOM tab**: lazy-loaded on tab click; shows component table (name, version, ecosystem, licenses, purl)
- **Policy Results tab**: lazy-loaded on tab click; shows pass/warn/fail badge and violations list
- Header: shows `base_image` + `base_image_chain` for container scans; scanner engine badge; rerun button (navigates to new scan on success)

### `Policies.tsx`

Full CRUD with `PolicyRuleEditor` component for adding/editing rules.

### `SBOMViewer.tsx`

Standalone page for viewing the SBOM of a scan by `scanId` URL param.

### `Settings.tsx`

Renders all settings from `GET /api/settings`. Currently only `scanner_backend` is configurable.

### `Workers.tsx`

Rack-unit visualisation:
- 3 `ServerUnit` components, each with 8 `Slot` components arranged in 2 rows of 4
- Running scans are distributed round-robin across workers
- LED colors: cyan (`#22d3ee`) for trivy, purple (`#a855f7`) for grype, amber (`#b45309`) for standby
- Active slots show a scan-line shimmer animation; LEDs blink; power button pulses; HDD light flickers
- Chassis top rail fills proportionally to load
- Pending queue rendered below the rack as a table
- CSS animations: `ledBlink`, `powerPulse`, `hddFlicker`, `slotScan` (defined inline as `<style>`)

### `AuditLog.tsx`

Filterable by `action` and `resource_type`; paginated; uses `GET /api/reports/audit-log`.

---

## Key Components

### `FindingCard.tsx`

- Collapsible row showing: vuln ID, package@version, severity badge, CVSS, fix availability
- Expanded view: description, fix version, risk score, ecosystem, exploitable flag, aliases, top 3 references
- **"View Full OSV Details"** toggle opens `OsvDetailPanel` (inline, lazy-fetched)

### `OsvDetailPanel` (inside `FindingCard.tsx`)

- Calls `GET /api/vulns/{vuln_id}` (backend proxy to OSV)
- Displays: published/modified dates, CWE IDs (linked to MITRE), full description, CVSS vectors, affected package ranges (introduced/fixed/last_affected), all references with type badges

### `PolicyRuleEditor.tsx`

- Supports all 4 rule types with appropriate inputs:
  - `severity_threshold`: select (CRITICAL/HIGH/MEDIUM/LOW)
  - `cvss_threshold`: number input (0–10, step 0.1)
  - `fix_available`: checkbox (require fix)
  - `package_blocklist`: textarea (one package name per line)

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

### Frontend (TypeScript/React)

- **Functional components** with React hooks only; no class components.
- Shared TypeScript interfaces live in `src/types.ts`; always use them, never inline `any` types in props.
- API calls go through typed functions in `src/api/`; use **TanStack Query** (`useQuery`, `useMutation`) for all data fetching and cache invalidation.
- UI components go in `src/components/`, full pages in `src/pages/`.
- Use the existing **CSS custom properties** (`--bg-card`, `--bg-primary`, `--bg-secondary`, `--border`, `--accent`, `--text-primary`, `--text-secondary`, `--critical`, `--high`, `--medium`, `--low`, `--success`, `--warning`, `--error`) — do not add a new CSS framework or reset the dark theme.
- Use inline styles with the CSS variable references; the project does not use CSS Modules or Tailwind.
- When adding a new scan-related polling query, use the `refetchInterval` callback pattern — return an interval in ms only while scans are active, otherwise `false`.

---

## Database Portability Notes (`docs/database-portability.md`)

The app is designed for SQLite but documented for PostgreSQL migration. **4 known blockers** before switching:

1. `connect_args={"check_same_thread": False}` in `database.py` — SQLite-only; needs conditional
2. Named `Enum` types (`scan_type_enum`, `severity_enum`, etc.) — PostgreSQL creates real DB types; `create_all()` will fail on re-deploy
3. No migration system — app uses `create_all()` only; needs Alembic for schema evolution
4. Test suite hardcodes `sqlite:///./test.db` — needs `TEST_DATABASE_URL` env var parameterization

The repository pattern and pure-ORM approach mean the fix surface is intentionally small. See `docs/database-portability.md` for the step-by-step migration procedure.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:////data/dunedain.db` | SQLAlchemy connection string |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery broker |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/0` | Celery result backend |
| `DUNEDAIN_CACHE_DIR` | `$TMPDIR` | Directory for file-based scan result cache |
| `DUNEDAIN_CACHE_TTL` | `3600` | Cache TTL in seconds |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins or `*` |
