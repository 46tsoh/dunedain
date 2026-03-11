# Dunedain Antipattern Analysis and Issue Backlog

Date: 2026-03-07

## Why this exists

This document converts the repo analysis into actionable GitHub issues. Items are grouped by impact and execution order so the team can improve reliability, security, and maintainability without stalling feature work.

## Priority 0 - Reliability and Security

### 1) Replace startup SQL migrations with Alembic

- **Problem:** Startup runs ad-hoc DDL (`ALTER TABLE ...`) and suppresses exceptions, which can hide failures and produce inconsistent schemas.
- **Evidence:** `backend/app/main.py`
- **Risk:** Hidden migration failures, environment drift, hard-to-debug deploy breakage.
- **Expected outcome:** Deterministic, reviewable schema migrations with clear failure modes.

### 2) Harden settings validation for scanner backends

- **Problem:** `scanner_backend` and `comparison_backend` accept any string; unknown values degrade into odd fallback behavior.
- **Evidence:** `backend/app/routers/settings.py`, `backend/app/services/scanner.py`
- **Risk:** Misconfiguration silently changes scanner behavior in production.
- **Expected outcome:** Strict enum validation and safe defaults.

### 3) Stop storing registry passwords in plaintext

- **Problem:** Registry credentials are persisted directly in DB fields.
- **Evidence:** `backend/app/models.py`, `backend/app/routers/registries.py`
- **Risk:** Credential exposure via DB access, dumps, logs, and backups.
- **Expected outcome:** Encrypted-at-rest secrets or external secret store integration.

## Priority 1 - Scalability and Data Access

### 4) Remove N+1 query patterns from scan and dashboard routes

- **Problem:** Severity counts and trend computations iterate related objects with per-row lookups.
- **Evidence:** `backend/app/routers/scans.py`, `backend/app/routers/reports.py`
- **Risk:** Latency and DB load increase nonlinearly as data grows.
- **Expected outcome:** Aggregated SQL queries and/or eager loading.

### 5) Add pagination/infinite scrolling in frontend scans list

- **Problem:** Frontend always requests `limit=100` and does not paginate.
- **Evidence:** `frontend/src/api/scans.ts`, `frontend/src/pages/Scans.tsx`
- **Risk:** Slower UI and larger payloads as scan history grows.
- **Expected outcome:** Paginated UX aligned with backend query parameters.

### 6) Revisit SQLite + high Celery concurrency defaults

- **Problem:** Multiple high-concurrency workers share a single SQLite DB file.
- **Evidence:** `docker-compose.yml`
- **Risk:** Lock contention and unstable throughput under load.
- **Expected outcome:** Tuned concurrency for SQLite and path toward PostgreSQL in production profiles.

## Priority 2 - Code Health and Operational Clarity

### 7) Break up scanner service god module

- **Problem:** `scanner.py` combines orchestration, tool execution, parsing, normalization, and enrichment in one very large file.
- **Evidence:** `backend/app/services/scanner.py`
- **Risk:** High regression surface and difficult ownership.
- **Expected outcome:** Modular scanner package with smaller, testable units.

### 8) Replace broad exception swallowing with structured errors/logging

- **Problem:** Critical paths catch broad exceptions and ignore them.
- **Evidence:** `backend/app/main.py`, `backend/app/tasks/scan.py`
- **Risk:** Silent failures and poor incident diagnostics.
- **Expected outcome:** Explicit exception handling with meaningful logs/metrics.

### 9) Clean up cache-related drift in task/API semantics

- **Problem:** `force` parameter and comments still reference cache bypass behavior that no longer exists.
- **Evidence:** `backend/app/tasks/scan.py`, `backend/app/routers/scans.py`
- **Risk:** Confusing behavior and maintenance mistakes.
- **Expected outcome:** Clear rerun semantics and removed stale parameters/docs.

### 10) Fix SBOM ingest semantic mismatch

- **Problem:** Ingest path computes a generated SBOM but stores raw payload content.
- **Evidence:** `backend/app/routers/sbom.py`
- **Risk:** Unclear contract and accidental dead code.
- **Expected outcome:** Decide and enforce one behavior (store input as-is vs normalized/generated form).

## Priority 3 - Frontend Maintainability

### 11) Refactor large inline-style pages into reusable view components

- **Problem:** `Scans.tsx`, `Workers.tsx`, and `ScanDetail.tsx` have grown large and tightly coupled.
- **Evidence:** `frontend/src/pages/Scans.tsx`, `frontend/src/pages/Workers.tsx`, `frontend/src/pages/ScanDetail.tsx`
- **Risk:** Slower iteration and harder UI testing.
- **Expected outcome:** Smaller components with clearer responsibilities.

### 12) Make Workers page capacity dynamic

- **Problem:** Worker/slot capacity is hardcoded (`3 x 8`) and may diverge from deployment.
- **Evidence:** `frontend/src/pages/Workers.tsx`
- **Risk:** Misleading operational dashboard.
- **Expected outcome:** Capacity values sourced from backend config/endpoint.

## Test and CI integrity

### 13) Fix service tests importing removed cache module

- **Problem:** Tests reference `app.services.cache`, but module is absent.
- **Evidence:** `backend/tests/test_services.py`
- **Risk:** CI noise and reduced confidence in test signal.
- **Expected outcome:** Green tests aligned with current architecture.

### 14) Extend CI to include frontend lint and stricter backend test env parity

- **Problem:** CI builds frontend but does not run lint, and backend local parity around tooling can drift.
- **Evidence:** `.github/workflows/ci.yml`
- **Risk:** Style/type regressions and environment-specific failures.
- **Expected outcome:** Stronger automated quality gates.
