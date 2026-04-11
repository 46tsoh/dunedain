# backend/app — Backend Application Layer

## OVERVIEW

FastAPI backend split by responsibility: HTTP adapters (`routers`) + DB abstraction (`repositories`) + pure logic (`services`) + async orchestration (`tasks`).

## STRUCTURE

```
app/
├── main.py              # Lifespan setup, CORS, router mount (11 routers), default policy seeding, Alembic upgrade
├── models.py            # 17 ORM entities; UUID PKs; relationship cascades
├── schemas.py           # Pydantic v2 response/request models + computed helpers (~40 schemas)
├── database.py          # SQLAlchemy engine + SessionLocal (SQLite default, PostgreSQL in Docker)
├── celery_app.py        # Celery config: task routes, beat schedule, time limits
├── repositories/
│   ├── base.py          # BaseRepository[T] generic CRUD (get, get_or_404, list, count, add, save, delete, etc.)
│   └── repos.py         # 20 concrete repository classes
├── services/
│   ├── scanner.py       # Scanner dispatch (Trivy/Grype/OSV), manifest parsing, dedup, base image extraction
│   ├── policy.py        # Policy rule evaluation (4 rule types)
│   ├── risk.py          # Risk score computation + finding prioritization
│   ├── sbom.py          # CycloneDX SBOM generation + SBOM parsing (CycloneDX/SPDX)
│   ├── cache.py         # File-based scan result cache (SHA-256 key, TTL)
│   ├── registry.py      # Container registry connectivity (ACR, Docker Hub, GHCR)
│   ├── msrc.py          # Microsoft Security Response Center advisory cache
│   ├── ticketing/
│   │   ├── __init__.py      # get_provider() factory function
│   │   ├── base.py          # TicketingProvider ABC + dataclasses (TicketResult, TestResult)
│   │   ├── jira_provider.py # JiraProvider: Jira REST API v2/v3 integration
│   │   ├── github_provider.py # GitHubIssuesProvider: GitHub REST API v2022-11-28 integration
│   │   ├── field_mapper.py  # build_ticket_fields(): Finding→provider field transformation (Jira fields, GitHub labels)
│   │   ├── auto_tickets.py  # Auto-ticket creation for teams with auto_create_tickets enabled
│   │   ├── registry.py      # Provider registry (pluggable provider discovery)
│   │   ├── webhook_processor.py  # Jira webhook: parse_jira_event, classify_event_triggers, process_webhook_event, verify_hmac_signature
│   │   └── github_webhook_processor.py  # parse_github_event, classify_github_triggers, process_github_webhook_event, verify_github_signature
│   └── automation/
│       ├── __init__.py
│       └── engine.py        # evaluate_automation_rules(): condition matching + action execution
├── tasks/
│   ├── scan.py          # Celery task: run_scan (full pipeline: scan → deduplicate → persist → risk → policy → SBOM → auto-tickets → internal events)
│   ├── registry_sync.py # Celery tasks: sync_registry, sync_all_registries (beat-scheduled every 5 min)
│   ├── msrc_refresh.py  # Celery task: refresh_msrc_cache (beat-scheduled daily at 3 AM UTC)
│   └── automation.py    # Celery tasks: process_webhook_event, fire_internal_event
└── routers/
    ├── scans.py         # Scan CRUD + findings/sbom/policy-results sub-resources
    ├── policies.py      # Policy CRUD + on-demand evaluate endpoint
    ├── reports.py       # Dashboard stats + audit log
    ├── sbom.py          # SBOM ingest + get-by-id
    ├── settings.py      # App settings key-value store
    ├── vulns.py         # OSV.dev proxy (deep-dive)
    ├── registries.py    # Registry CRUD + sync/test/repos sub-resources
    ├── teams.py         # Team CRUD + ownership rules + team dashboard
    ├── integrations.py  # Integration CRUD + tickets + bulk tickets + webhook registration + ticket comments
    ├── webhooks.py      # Jira + GitHub webhook receivers + event log + retry
    └── automation.py    # Automation rule CRUD + trigger list + execution history + toggle
```

## HOT PATHS

- **Scan lifecycle:** `routers/scans.py` → `tasks/scan.py` → `services/scanner.py` + `services/policy.py` + `services/sbom.py` + `services/ticketing/auto_tickets.py` → `tasks/automation.fire_internal_event`
- **Registry sync:** `routers/registries.py` + `tasks/registry_sync.py` + `services/registry.py`
- **Ticketing lifecycle:** `routers/integrations.py` → `services/ticketing/field_mapper.py` → `services/ticketing/{jira_provider,github_provider}.py`
- **Webhook processing:** `routers/webhooks.py` → `tasks/automation.process_webhook_event` → `services/ticketing/{webhook_processor,github_webhook_processor}.py` → `services/automation/engine.py`
- **Automation engine:** `tasks/automation.fire_internal_event` → `services/automation/engine.py` (conditions → actions)
- **Reporting:** `routers/reports.py` + `repositories/repos.py` aggregations

## DATA FLOW (SCAN)

```
POST /api/scans
  → create Scan(status=pending)
  → celery run_scan.delay(scan_id)
  → worker sets running
  → scanner dispatch (container/source/dependency)
  → deduplicate findings (by vuln_id+package_name+version; prefer higher CVSS)
  → persist findings + prioritize risk
  → upsert VulnerabilityInstance rows
  → evaluate enabled policies
  → generate CycloneDX SBOM
  → auto-assign team via ownership rules
  → auto-create tickets (if team has auto_create_tickets enabled)
  → mark completed + audit log
  → fire_internal_event("scan_completed", context)
  → fire_internal_event("policy_violated", context)  # for each failed policy
```

## DATA FLOW (WEBHOOK → AUTOMATION)

```
POST /api/webhooks/jira/{integration_id}
  → verify HMAC signature (if webhook_secret configured)
  → persist WebhookEvent(status=received)
  → celery process_webhook_event.delay(event_id)
  → worker: parse_jira_event(payload)
  → process_webhook_event(): update ticket status/assignee/priority
  → classify_event_triggers(): determine triggers (e.g. jira_status_changed)
  → evaluate_automation_rules(trigger, context):
      → for each enabled rule matching trigger:
          → evaluate conditions (severity_gte, cvss_gte, status_equals, etc.)
          → if conditions match: execute actions (create_ticket, add_comment, transition_ticket, etc.)
          → persist AutomationRuleExecution
  → set event status=processed + audit log

POST /api/webhooks/github/{integration_id}
  → verify X-Hub-Signature-256 (HMAC-SHA256)
  → persist WebhookEvent(status=received)
  → celery process_webhook_event.delay(event_id)
  → worker: parse_github_event(payload)
  → process_github_webhook_event(): update ticket status/assignee/labels
  → classify_github_triggers(): determine triggers (e.g. ticket_status_changed)
  → evaluate_automation_rules(trigger, context)
  → set event status=processed + audit log
```

## FILE-LEVEL GUIDANCE

| Change | Primary file(s) | Notes |
|---|---|---|
| New API behavior | `routers/*.py` + `schemas.py` | Keep router thin; push logic down |
| New DB query | `repositories/repos.py` | Add typed method; reuse in router/task |
| New scan capability | `services/scanner.py` | Preserve fallback chain + dedup semantics |
| New policy rule | `services/policy.py` + `schemas.py` | Update rule evaluator + API shape |
| Scan pipeline step | `tasks/scan.py` | Maintain status transitions + audit consistency |
| New ticketing provider | `services/ticketing/base.py` → implement ABC, register in `registry.py` | Follow JiraProvider or GitHubIssuesProvider pattern |
| Ticket field mapping | `services/ticketing/field_mapper.py` | Uses IntegrationFieldMapping rows |
| Webhook processing | `services/ticketing/webhook_processor.py` | Parse payload → classify triggers → update state |
| Automation condition | `services/automation/engine.py` | Add to `_evaluate_condition()` match |
| Automation action | `services/automation/engine.py` | Add to `_execute_action()` match |
| New internal event | `tasks/scan.py` or caller + `tasks/automation.py` | Call `fire_internal_event.delay(trigger, context)` |

## AUTOMATION ENGINE REFERENCE

**14 triggers:** `jira_status_changed`, `jira_priority_changed`, `jira_comment_added`, `jira_assignee_changed`, `jira_issue_deleted`, `ticket_status_changed`, `ticket_comment_added`, `ticket_assignee_changed`, `ticket_deleted`, `ticket_label_changed`, `scan_completed`, `finding_fixed`, `finding_regressed`, `policy_violated`

**15 conditions (canonical + frontend aliases):** `severity_in`, `severity_gte`, `cvss_min`, `cvss_max`, `cvss_gte` (alias→cvss_min), `team_id`, `team_equals` (alias→team_id), `integration_id`, `jira_status_in`, `ticket_status_in`, `package_name_matches`, `package_matches` (alias→package_name_matches), `status_equals`, `priority_equals`, `ecosystem_equals`, `has_fix`, `scan_type`

**10 actions (with aliases):** `create_ticket`, `add_comment`/`add_ticket_comment`/`add_jira_comment`, `transition_ticket`/`transition_jira_ticket`, `update_ticket_fields`/`update_jira_fields`, `mark_finding_accepted`/`accept_risk`, `log_audit_event`, `rerun_scan`, `send_notification`, `update_priority`

## KNOWN TECH-DEBT EDGES

- Broad exception handlers still exist in scanner/registry areas; prefer narrowing when touching
- `cache.py` is no longer used in Docker Compose (file cache on shared volume); only relevant for local dev
- Webhook HMAC verification supports Jira Cloud (`X-Atlassian-Webhook-Signature`) and GitHub (`X-Hub-Signature-256`) signature formats

## MIGRATION NOTES

- Schema managed by Alembic (`backend/migrations/`); `main.py` runs `alembic upgrade head` on startup after `create_all`
- 9 migrations: `0001_column_additions` → `0002_teams_ownership` → `0003_sla_global_only` → `0004_vulnerability_instances` → `0005_integrations` → `0006_team_auto_tickets` → `0007_webhooks_automation_rules` → `0008_ticket_indexes` → `0009_comment_dedup_constraint`
- `render_as_batch=True` in `env.py` provides SQLite DDL compatibility; safe for PostgreSQL too
- Future schema changes: add a new `migrations/versions/` file rather than editing existing ones
- All migrations guard column operations with existence checks to remain idempotent with `create_all`

## TESTING

```bash
# From repo root — works on any host Python version (system Python may be 3.9):
docker run --rm -v "$(pwd)/backend:/app" -w /app python:3.12-slim bash -c \
  "pip install -r requirements.txt pytest pytest-asyncio httpx 2>&1 | tail -3 && pytest tests/ -v 2>&1"

# Inside devcontainer (Python 3.12 guaranteed):
cd backend && pytest tests/ -v
```

- `conftest.py` stubs Celery `.delay()` to avoid broker dependency
- `test_api.py` exercises HTTP contract + persistence side effects (17 tests)
- `test_services.py` covers parser/fallback/risk/automation logic with mocked subprocess + HTTP (52 tests)
