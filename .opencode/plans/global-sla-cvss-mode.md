# Plan: Global-Only SLA with Severity/CVSS Mode Toggle

## Summary
Remove per-team SLA overrides entirely. Make SLA a global-only setting with two modes:
- **Severity mode** (default): deadlines based on finding severity (CRITICAL/HIGH/MEDIUM/LOW)
- **CVSS mode**: deadlines based on CVSS score ranges with configurable thresholds. Findings without a CVSS score fall back to severity-based lookup.

## New Global Settings (`app_settings` table)

| Key | Default | Description |
|---|---|---|
| `sla_mode` | `"severity"` | `"severity"` or `"cvss"` |
| `sla_critical_hours` | `"24"` | (exists — update description) |
| `sla_high_hours` | `"72"` | (exists — update description) |
| `sla_medium_hours` | `"168"` | (exists — update description) |
| `sla_low_hours` | `"720"` | (exists — update description) |
| `sla_cvss_critical_min` | `"9.0"` | CVSS floor for critical tier |
| `sla_cvss_high_min` | `"7.0"` | CVSS floor for high tier |
| `sla_cvss_medium_min` | `"4.0"` | CVSS floor for medium tier |

In CVSS mode, the 4 existing `sla_*_hours` keys are reused for the CVSS tiers (critical range hours = `sla_critical_hours`, etc). Scores below `sla_cvss_medium_min` use `sla_low_hours`.

---

## Backend Changes

### 1. `routers/settings.py` — Add new keys to `_KNOWN_SETTINGS`

Add `sla_mode` and 3 `sla_cvss_*_min` keys. Update descriptions on existing `sla_*_hours` keys to remove "Teams can override" language and mention both modes.

### 2. `models.py` — Remove team SLA columns

Remove `sla_critical_hours`, `sla_high_hours`, `sla_medium_hours`, `sla_low_hours` from the `Team` model.

### 3. `migrations/versions/0003_sla_global_only.py` — New migration

Drop the 4 `sla_*_hours` columns from the `teams` table. Use idempotent guards (`_column_names` check) and `batch_alter_table` for SQLite compatibility.

### 4. `schemas.py` — Remove SLA fields from Team schemas

- `TeamBase`: remove `sla_critical_hours`, `sla_high_hours`, `sla_medium_hours`, `sla_low_hours`
- `TeamUpdate`: remove same 4 fields
- `TeamFindingSummary`: remove `sla_source` field (always global now, no value in distinguishing)

### 5. `routers/teams.py` — Rewrite SLA logic

**Remove:**
- `sla_*_hours` assignments in `create_team` and `update_team`
- `sla_*_hours` in `_team_to_read`
- The old `_sla_hours_for_severity()` function

**Add new `_resolve_sla_hours(severity, cvss_score, db)` function:**
```python
def _resolve_sla_hours(severity: str, cvss_score: float | None, db: Session) -> int | None:
    settings = SettingRepository(db)
    mode = settings.get_value("sla_mode", default="severity")
    
    if mode == "cvss" and cvss_score is not None:
        # Read thresholds
        critical_min = float(settings.get_value("sla_cvss_critical_min", default="9.0"))
        high_min = float(settings.get_value("sla_cvss_high_min", default="7.0"))
        medium_min = float(settings.get_value("sla_cvss_medium_min", default="4.0"))
        
        if cvss_score >= critical_min:
            key = "sla_critical_hours"
        elif cvss_score >= high_min:
            key = "sla_high_hours"
        elif cvss_score >= medium_min:
            key = "sla_medium_hours"
        else:
            key = "sla_low_hours"
    else:
        # Severity mode, or CVSS mode with null score (fallback)
        key_map = {"CRITICAL": "sla_critical_hours", "HIGH": "sla_high_hours",
                   "MEDIUM": "sla_medium_hours", "LOW": "sla_low_hours"}
        key = key_map.get(severity.upper())
        if key is None:
            return None
    
    raw = settings.get_value(key, default="")
    try:
        return int(raw) if raw else None
    except (ValueError, TypeError):
        return None
```

**Update dashboard endpoint:**
- Call `_resolve_sla_hours(f.severity, f.cvss_score, db)` instead of the old function
- Remove `sla_source` from `TeamFindingSummary` construction

---

## Frontend Changes

### 6. `types.ts` — Remove team SLA fields

- `Team` interface: remove `sla_critical_hours`, `sla_high_hours`, `sla_medium_hours`, `sla_low_hours`
- `TeamFindingSummary` interface: remove `sla_source`

### 7. `api/teams.ts` — Remove SLA from payloads

- `createTeam`: remove `sla_*_hours` params
- `updateTeam`: remove `sla_*_hours` params

### 8. `pages/Teams.tsx` — Remove SLA config UI

Remove:
- State variables: `slaCritical`, `slaHigh`, `slaMedium`, `slaLow`, `editSlaCritical`, `editSlaHigh`, `editSlaMedium`, `editSlaLow`
- SLA section from create modal (the `borderTop` div with Clock icon + 4 number inputs)
- SLA section from edit modal (same)
- SLA fields from `handleCreate()` and `handleUpdate()` payloads
- SLA fields from `openEdit()` function
- SLA summary row on team cards (lines 367-375)
- `Clock` from lucide-react import if no longer used

### 9. `pages/TeamDashboard.tsx` — Simplify SLA display

Replace the "SLA Configuration" card (which shows team-level sla_critical_hours etc) with a simpler panel:
- Fetch global settings via `useQuery` for `/api/settings`
- Show the active SLA mode ("Severity-based" or "CVSS-based")
- Show the current thresholds from global settings
- Link to Settings page to configure

Remove:
- `sla_source`-based labels on findings (`"global default"`, `"(global)"`)
- The team SLA null-check conditional (lines 187-205)

### 10. `pages/Settings.tsx` — Add SLA mode toggle + CVSS config

Expand the `SlaSection` component:
- Add a mode toggle at the top (radio buttons: "By Severity" / "By CVSS Score")
- When severity mode: show existing 4 hour inputs (as-is)
- When CVSS mode: show 3 threshold inputs (critical min, high min, medium min) + 4 hour inputs with labels like "CVSS >= 9.0: __ hours"
- Update subtitle text to remove "Teams can override" language
- Mode toggle saves the `sla_mode` setting immediately on click

### 11. Lint, build, deploy, verify

```bash
cd frontend && npm run lint && npm run build
docker compose up -d --build
# Verify endpoints:
curl http://localhost:8001/api/settings  # should show sla_mode + cvss keys
curl http://localhost:8001/api/teams/TEAM_ID/dashboard  # should work with no sla_source
```

---

## Files Modified

| File | Action |
|---|---|
| `backend/app/routers/settings.py` | Add `sla_mode` + 3 `sla_cvss_*_min` keys; update descriptions |
| `backend/app/models.py` | Remove 4 `sla_*_hours` columns from `Team` |
| `backend/app/schemas.py` | Remove SLA fields from `TeamBase`/`TeamUpdate`; remove `sla_source` from `TeamFindingSummary` |
| `backend/app/routers/teams.py` | Remove team SLA in CRUD; replace `_sla_hours_for_severity` with `_resolve_sla_hours`; clean up dashboard |
| `backend/migrations/versions/0003_sla_global_only.py` | **NEW** — drop team SLA columns |
| `frontend/src/types.ts` | Remove team SLA fields + `sla_source` |
| `frontend/src/api/teams.ts` | Remove SLA from create/update payloads |
| `frontend/src/pages/Teams.tsx` | Remove SLA config UI from modals + cards |
| `frontend/src/pages/TeamDashboard.tsx` | Replace team SLA panel with global SLA display |
| `frontend/src/pages/Settings.tsx` | Add mode toggle + CVSS range config |
