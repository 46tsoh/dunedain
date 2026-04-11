# Dunedain — Repo Root

## WHAT IS THIS

Self-hostable software supply chain security platform. Scans containers, source code, and dependencies for vulnerabilities; enforces policy; prioritises risk; integrates with Jira and GitHub Issues for ticketing; fires automation rules on webhook events.

## TOP-LEVEL LAYOUT

```
dunedain/
├── backend/            # Python 3.12 FastAPI + Celery + SQLAlchemy + PostgreSQL
├── frontend/           # React 19 + TypeScript + Vite SPA
├── docker-compose.yml  # Production stack (8 services)
├── .devcontainer/      # Dev environment (Python 3.12, Node 20, scanners pre-installed)
└── docs/               # Architecture diagrams
```

## RUNNING THE FULL STACK

```bash
docker compose up -d --build
```

Services: `postgres`, `redis`, `backend` (:1337), `frontend` (:80), `worker-scans`, `worker-webhooks`, `worker-default`, `beat`

- UI:       http://localhost
- API:      http://localhost:1337
- API docs: http://localhost:1337/docs

## DEVELOPMENT (devcontainer — recommended)

The devcontainer gives every developer an identical environment with Python 3.12, Node 20, Trivy, Grype, Syft, osv-scanner, Docker CLI, Postgres, and Redis pre-configured.

```bash
# VS Code / Cursor: install Dev Containers extension, then "Reopen in Container"

# CLI only:
npm install -g @devcontainers/cli
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

Once inside:

```bash
# Terminal 1 — backend with hot reload
cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 1337

# Terminal 2 — celery worker
cd backend && celery -A app.celery_app worker --loglevel=info -Q scans

# Terminal 3 — frontend dev server
cd frontend && npm run dev   # http://localhost:5173
```

## SYSTEM PYTHON WARNING

**Never run `pytest` directly on the host.** The host Python may be 3.9 or older and will fail to install deps. Use Docker or the devcontainer (both guarantee Python 3.12).

## VERIFICATION COMMANDS

```bash
# Backend tests (works on any host — no local Python required)
docker run --rm -v "$(pwd)/backend:/app" -w /app python:3.12-slim bash -c \
  "pip install -r requirements.txt pytest pytest-asyncio httpx 2>&1 | tail -3 && pytest tests/ -v 2>&1"

# Frontend lint + build
cd frontend && npm run lint && npm run build
```

## WHERE TO GO NEXT

| Area | AGENTS.md |
|---|---|
| Backend (routers, services, tasks, automation) | `backend/app/AGENTS.md` |
| Backend (testing, migrations, deps) | `backend/AGENTS.md` |
| Frontend (pages, components, API, types) | `frontend/src/AGENTS.md` |

## TECH STACK SUMMARY

- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Celery + Redis, PostgreSQL
- **Frontend**: React 19, TypeScript, Vite, TanStack Query v5, Axios, Lucide icons
- **Scanners**: Trivy, Grype, Syft, osv-scanner
- **Ticketing**: Jira Cloud, GitHub Issues (pluggable provider architecture)
- **Deployment**: Docker Compose (8 services)
