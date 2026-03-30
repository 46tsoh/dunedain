# Dunedain

An open-source, self-hostable software supply chain security platform that helps teams scan containers, code, and dependencies, enforce policy, prioritize real risk, and remediate faster using transparent vulnerability intelligence powered by [osv.dev](https://osv.dev).

## Features

- **Vulnerability Scanning** — Scan containers, application dependencies (npm, PyPI, Go, Maven, Cargo), and source code for known vulnerabilities using the osv.dev API
- **Web UI** — A modern, dark-themed dashboard to view findings, trends, and remediation status
- **Scan Caching** — Cached scan results reduce repeated API calls and speed up CI/CD pipelines
- **Policy Enforcement** — Define blocking, warning, or audit policies with rules for severity, CVSS score, fix availability, and package blocklists
- **SBOM Support** — Generate CycloneDX SBOMs for every scan, ingest existing SBOMs for analysis
- **Risk Prioritization** — Findings ranked by risk score combining severity, CVSS, exploitability, and reachability
- **Registry Integration** — Browse and scan images directly from ACR, Docker Hub, GHCR, and generic OCI registries with auto-scan on new tags
- **CI/CD Integration** — GitHub Actions workflows and REST API for pipeline security gates
- **Audit Log** — Full record of scans, policy evaluations, and platform actions
- **REST API** — Full OpenAPI-documented API for custom integrations

## Quick Start

### Using Docker Compose (recommended)

```bash
git clone https://github.com/marekx/dunedain
cd dunedain
docker compose up -d
```

- **Web UI**: http://localhost
- **API**: http://localhost:1337
- **API Docs**: http://localhost:1337/docs

### Local Development (devcontainer — recommended)

The repo ships with a devcontainer that gives every developer an identical environment: Python 3.12, Node 20, Trivy, Grype, Syft, osv-scanner, Docker CLI, Postgres, and Redis — all pre-configured, nothing installed on your host machine.

**Option A — VS Code / Cursor**

1. Install the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Open the repo, then **Reopen in Container** when prompted
3. The container builds, migrations run, and dependencies install automatically

**Option B — CLI only** (no IDE required)

```bash
# Install the devcontainer CLI once
npm install -g @devcontainers/cli

# Start the environment
devcontainer up --workspace-folder .

# Open a shell inside it
devcontainer exec --workspace-folder . bash
```

**Option C — plain Docker Compose**

```bash
docker compose -f .devcontainer/docker-compose.dev.yml up -d
docker compose -f .devcontainer/docker-compose.dev.yml exec devcontainer bash
```

**Once inside the container**, start the services:

```bash
# Terminal 1 — backend with hot reload
cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 1337

# Terminal 2 — celery worker
cd backend && celery -A app.celery_app worker --loglevel=info -Q scans

# Terminal 3 — frontend dev server (opens at http://localhost:5173)
cd frontend && npm run dev
```

> **Note:** `docker compose up` (the production stack) still works from inside the devcontainer — the Docker socket is mounted so the CLI talks to your host daemon.

## CI/CD Integration

Trigger a scan and gate your pipeline via the REST API:

```bash
# 1. Start a scan (returns scan ID)
SCAN_ID=$(curl -s -X POST http://localhost/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "your-image:tag", "scan_type": "container"}' \
  | jq -r '.id')

# 2. Poll until complete
while true; do
  STATUS=$(curl -s http://localhost/api/scans/$SCAN_ID | jq -r '.status')
  [ "$STATUS" = "completed" ] && break
  [ "$STATUS" = "failed" ] && echo "Scan failed" && exit 1
  sleep 5
done

# 3. Check policy result — exit 1 if any policy fails
RESULT=$(curl -s "http://localhost/api/scans/$SCAN_ID/policy-results" \
  | jq -r '.[].result' | grep -c "fail" || true)
[ "$RESULT" -gt 0 ] && echo "Policy gate FAILED" && exit 1
echo "Policy gate PASSED"
```

Or add it to a GitHub Actions workflow:

```yaml
- name: Security gate
  env:
    SCAN_API: http://your-platform-host/api
  run: |
    SCAN_ID=$(curl -s -X POST $SCAN_API/scans \
      -H "Content-Type: application/json" \
      -d "{\"target\": \"$IMAGE\", \"scan_type\": \"container\"}" \
      | jq -r '.id')
    # ... poll and check policy results as above
```

## API Reference

Full OpenAPI docs available at `/docs` when the backend is running.

Key endpoints:
- `POST /api/scans` — Trigger a new scan
- `GET /api/scans` — List all scans
- `GET /api/scans/{id}/findings` — Get findings for a scan
- `POST /api/policies` — Create a security policy
- `GET /api/reports/dashboard` — Get summary statistics
- `POST /api/sbom/ingest` — Ingest an SBOM for scanning
- `GET /api/registries` — List connected registries
- `GET /api/registries/{id}/repositories/search` — Search repos in a registry

## Policy Rules

Policies consist of one or more rules:

| Rule Type | Description | Example |
|-----------|-------------|---------|
| `severity_threshold` | Block/warn by severity level | `{"type": "severity_threshold", "min_severity": "HIGH"}` |
| `cvss_threshold` | Block/warn by CVSS score | `{"type": "cvss_threshold", "min_score": 7.0}` |
| `fix_available` | Require a fix to exist | `{"type": "fix_available", "require_fix": true}` |
| `package_blocklist` | Block specific packages | `{"type": "package_blocklist", "packages": ["log4j"]}` |

## Architecture

```
┌──────────────┐    ┌──────────────────┐    ┌─────────────┐
│   Frontend   │───▶│  FastAPI Backend │───▶│  osv.dev API│
│  React + TS  │    │  Python 3.12     │    │  (public)   │
└──────────────┘    └──────────────────┘    └─────────────┘
                           │
               ┌───────────┼───────────┐
               ▼           ▼           ▼
        ┌────────────┐ ┌───────┐ ┌──────────┐
        │ PostgreSQL │ │ Redis │ │  Celery  │
        │  (schema)  │ │(queue)│ │ Workers  │
        └────────────┘ └───────┘ └──────────┘
```

## Tech Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy, PostgreSQL, Celery
- **Frontend**: React 19, TypeScript, Vite, React Query, Recharts
- **Scanners**: Trivy, Grype, Syft, osv-scanner
- **Vulnerability Data**: [osv.dev](https://osv.dev) open vulnerability database
- **SBOM Format**: CycloneDX 1.4
- **Deployment**: Docker, Docker Compose

## License

Elastic License 2.0 (ELv2) — source available, free for internal use, commercial SaaS use prohibited. See [LICENSE](LICENSE).
