# backend/ — Backend Entry Point

## LAYOUT

```
backend/
├── app/              # Application source (see app/AGENTS.md for full detail)
├── migrations/       # Alembic schema migrations
│   └── versions/     # 0001 → 0009 (sequential; never edit existing files)
├── tests/
│   ├── conftest.py       # SQLite in-memory DB + Celery .delay() stub
│   ├── test_api.py       # HTTP contract + persistence tests (17 tests)
│   └── test_services.py  # Parser/logic/risk/automation unit tests (52 tests)
├── requirements.txt  # Fully pinned deps (Python 3.12)
├── alembic.ini       # Alembic config (reads DATABASE_URL env var)
└── Dockerfile        # python:3.12-slim; runs alembic upgrade head on start
```

## SYSTEM PYTHON WARNING

**Do not run `pytest` directly on the host.** System Python may be 3.9 or older and will fail to install dependencies. Always use Docker or the devcontainer (Python 3.12).

## RUNNING TESTS

```bash
# From repo root — works on any host Python version:
docker run --rm -v "$(pwd)/backend:/app" -w /app python:3.12-slim bash -c \
  "pip install -r requirements.txt pytest pytest-asyncio httpx 2>&1 | tail -3 && pytest tests/ -v 2>&1"

# Inside devcontainer (Python 3.12 guaranteed):
cd backend && pytest tests/ -v
```

## TEST ARCHITECTURE

- `conftest.py` creates a fresh SQLite in-memory database per session and stubs `celery.app.task.Task.delay` so tasks enqueue without a broker
- `test_api.py` — full HTTP round-trips via FastAPI `TestClient`; exercises routers, repositories, and schema validation
- `test_services.py` — pure unit tests for scanner parsers, risk scoring, MSRC matching, and automation engine helpers; uses `unittest.mock.patch` for subprocess and HTTP calls

## ADDING A MIGRATION

1. Create `migrations/versions/00NN_short_description.py` (next sequential number)
2. Follow the existing pattern: `upgrade()` + `downgrade()`, guard column additions with existence checks for idempotency
3. `main.py` runs `alembic upgrade head` on startup — no manual step needed in Docker

Migration chain:
`0001_column_additions` → `0002_teams_ownership` → `0003_sla_global_only` → `0004_vulnerability_instances` → `0005_integrations` → `0006_team_auto_tickets` → `0007_webhooks_automation_rules` → `0008_ticket_indexes` → `0009_comment_dedup_constraint`

## DEPENDENCIES

`requirements.txt` is fully pinned (`==`) except `regipy` (no stable release tag). Add new deps with an exact version.

Notable non-obvious deps:
- `packaging==24.1` — used by the automation engine (`services/automation/engine.py`) for PEP 440 semver tag comparison when resolving the newest container image tag for `rerun_scan`
- `regipy` — Windows registry hive parsing (used by scanner for Windows image analysis)

## ENVIRONMENT VARIABLES (Docker Compose)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy connection string (PostgreSQL in Docker, SQLite in tests) |
| `REDIS_URL` | Celery broker + result backend |
| `SECRET_KEY` | HMAC signing for webhook secrets |

## FURTHER READING

See `app/AGENTS.md` for the full application layer: routers, services, repositories, tasks, automation engine reference, and data flow diagrams.
