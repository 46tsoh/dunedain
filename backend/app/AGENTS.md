# backend/app — Backend Application Layer

## OVERVIEW

FastAPI backend split by responsibility: HTTP adapters (`routers`) + DB abstraction (`repositories`) + pure logic (`services`) + async orchestration (`tasks`).

## STRUCTURE

```
app/
├── main.py              # Lifespan setup, CORS, router mount, default policy seeding
├── models.py            # ORM entities; UUID PKs; relationship cascades
├── schemas.py           # Pydantic v2 response/request models + computed helpers
├── repositories/        # BaseRepository + concrete repos per entity
├── services/            # Scanner/policy/risk/sbom/registry/cache logic
├── tasks/               # Celery task pipelines (scan + registry sync)
└── routers/             # `/api/*` endpoints; thin orchestration only
```

## HOT PATHS

- Scan lifecycle: `routers/scans.py` → `tasks/scan.py` → `services/scanner.py` + `services/policy.py` + `services/sbom.py`
- Registry sync: `routers/registries.py` + `tasks/registry_sync.py` + `services/registry.py`
- Reporting: `routers/reports.py` + `repositories/repos.py` aggregations

## DATA FLOW (SCAN)

```
POST /api/scans
  → create Scan(status=pending)
  → celery run_scan.delay(scan_id)
  → worker sets running
  → scanner dispatch (container/source/dependency)
  → deduplicate findings (by vuln_id+package_name+version; prefer higher CVSS)
  → persist findings + prioritize risk
  → evaluate enabled policies
  → generate CycloneDX SBOM
  → mark completed + audit log
```

## FILE-LEVEL GUIDANCE

| Change | Primary file(s) | Notes |
|---|---|---|
| New API behavior | `routers/*.py` + `schemas.py` | Keep router thin; push logic down |
| New DB query | `repositories/repos.py` | Add typed method; reuse in router/task |
| New scan capability | `services/scanner.py` | Preserve fallback chain + dedup semantics |
| New policy rule | `services/policy.py` + `schemas.py` | Update rule evaluator + API shape |
| Scan pipeline step | `tasks/scan.py` | Maintain status transitions + audit consistency |

## KNOWN TECH-DEBT EDGES

- Broad exception handlers still exist in scanner/registry areas; prefer narrowing when touching

## MIGRATION NOTES

- Schema managed by Alembic (`backend/migrations/`); `main.py` runs `alembic upgrade head` on startup after `create_all`
- `render_as_batch=True` in `env.py` provides SQLite DDL compatibility; safe for PostgreSQL too
- Future schema changes: add a new `migrations/versions/` file rather than editing existing ones

## TESTING

```bash
cd backend && pytest tests/ -v
```

- `conftest.py` stubs Celery `.delay()` to avoid broker dependency
- `test_api.py` exercises HTTP contract + persistence side effects
- `test_services.py` covers parser/fallback/risk logic with mocked subprocess + HTTP
