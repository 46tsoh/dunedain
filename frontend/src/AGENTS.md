# frontend/src — Frontend Application Layer

## OVERVIEW

React 19 + TypeScript + Vite SPA. Data flow via TanStack Query v5 + typed API clients. Styling is inline style objects + CSS variables from `index.css`.

## STRUCTURE

```
src/
├── App.tsx               # QueryClient setup + route tree (15 routes)
├── main.tsx              # React root mount
├── types.ts              # Shared domain interfaces (~25 interfaces, single source of truth)
├── utils.ts              # Helpers (`parseUTC`, formatting)
├── api/                  # Axios client + 11 domain API wrappers
│   ├── client.ts         # Axios instance (base URL, interceptors)
│   ├── scans.ts          # Scan CRUD + rerun + delete-all
│   ├── policies.ts       # Policy CRUD
│   ├── reports.ts        # Dashboard data + audit log
│   ├── sbom.ts           # SBOM fetch by scan
│   ├── vulns.ts          # OSV proxy
│   ├── settings.ts       # App settings
│   ├── registries.ts     # Registry CRUD + sync + test + repos
│   ├── teams.ts          # Team CRUD + ownership rules + team dashboard
│   ├── integrations.ts   # Integration CRUD + tickets + bulk tickets + test + sync + webhook registration (Jira + GitHub) + ticket comments
│   ├── webhooks.ts       # Webhook events list + detail + retry
│   └── automation.ts     # Automation rules CRUD + triggers + executions + toggle
├── components/           # 7 reusable UI blocks
│   ├── Layout.tsx             # Sidebar navigation (11 items) + outlet
│   ├── FindingCard.tsx        # Collapsible finding + nested OsvDetailPanel
│   ├── PolicyRuleEditor.tsx   # 4 policy rule types editor
│   ├── StatusBadge.tsx        # Scan status badge
│   ├── SeverityBadge.tsx      # Severity colored badge
│   ├── FieldMappingEditor.tsx # Integration field mapping editor (source, target_field, transform, template)
│   └── AutomationRuleEditor.tsx # Automation rule builder (trigger, conditions, actions)
├── pages/                # 14 route-level screens
│   ├── Dashboard.tsx          # Stats + severity chart + top vulns + recent scans
│   ├── Scans.tsx              # Scan table with create/delete/rerun + filters
│   ├── ScanDetail.tsx         # 3-tab detail (Findings / SBOM / Policy Results)
│   ├── Policies.tsx           # Policy CRUD with PolicyRuleEditor
│   ├── SBOMViewer.tsx         # Standalone SBOM component table
│   ├── AuditLog.tsx           # Filterable audit event log
│   ├── Settings.tsx           # App settings editor
│   ├── Workers.tsx            # Rack-unit visualisation (3 servers × 8 slots)
│   ├── Registries.tsx         # Registry CRUD + repository browsing + auto-sync/scan
│   ├── SeedScans.tsx          # Synthetic scan generation + progress
│   ├── Teams.tsx              # Team CRUD + ownership rules + auto-ticket config
│   ├── TeamDashboard.tsx      # Team-specific findings, SLA tracking, severity breakdown
│   ├── Integrations.tsx       # Integration CRUD (Jira + GitHub Issues) + tickets + webhooks + field mappings (~1070 lines)
│   └── AutomationRules.tsx    # Automation rule CRUD with AutomationRuleEditor (~500 lines)
└── index.css             # Theme tokens as CSS custom properties
```

## WHERE TO LOOK

| Task | File(s) | Pattern to follow |
|------|---------|-------------------|
| Add route/page | `App.tsx`, `pages/*`, `components/Layout.tsx` | Register `<Route>`, add nav item if needed |
| Add API call | `api/<domain>.ts` | Typed request/response; no inline axios in pages |
| Add field to UI models | `types.ts` | Update shared type first, then API + page usage |
| Adjust polling | Page `useQuery` blocks | Use `refetchInterval: (query) => ms \| false` |
| Add theme token | `index.css` | Use `var(--token)` in inline style objects |
| Add integration feature | `api/integrations.ts`, `pages/Integrations.tsx` | Follow ticket/webhook/comment patterns; provider-conditional UI for Jira vs GitHub
| Add automation feature | `api/automation.ts`, `pages/AutomationRules.tsx`, `components/AutomationRuleEditor.tsx` | Follow trigger/condition/action patterns |

## ROUTING MAP

- `/` → redirect to `/dashboard`
- `/dashboard` → `pages/Dashboard.tsx`
- `/scans` → `pages/Scans.tsx`
- `/scans/:id` → `pages/ScanDetail.tsx`
- `/policies` → `pages/Policies.tsx`
- `/sbom/:scanId` → `pages/SBOMViewer.tsx`
- `/audit-log` → `pages/AuditLog.tsx`
- `/settings` → `pages/Settings.tsx`
- `/workers` → `pages/Workers.tsx`
- `/registries` → `pages/Registries.tsx`
- `/teams` → `pages/Teams.tsx`
- `/teams/:teamId/dashboard` → `pages/TeamDashboard.tsx`
- `/integrations` → `pages/Integrations.tsx`
- `/automation` → `pages/AutomationRules.tsx`
- `/seed` → `pages/SeedScans.tsx`

## NAV SIDEBAR ORDER

Dashboard, Scans, Registries, Workers, Teams, Policies, Audit Log, Settings, Integrations, Automation, Seed Scans

## QUERY / POLLING CONTRACT

- Global QueryClient defaults (`App.tsx`): `retry: 1`, `refetchOnWindowFocus: false`
- `Scans.tsx`: poll every 3000ms only while any scan is `pending`/`running`
- `ScanDetail.tsx`: poll every 2000ms while current scan active
- `Workers.tsx`: poll every 1500ms (unconditional rack view)
- OSV deep-dive (`FindingCard.tsx`): `staleTime: 5 * 60 * 1000`

## QUERY KEY INVENTORY

| Key | Page / Component |
|-----|------------------|
| `['scans']` | Scans, Workers |
| `['scan', id]` | ScanDetail |
| `['findings', scanId]` | ScanDetail (findings tab) |
| `['sbom', scanId]` | ScanDetail (SBOM tab), SBOMViewer |
| `['policy-results', scanId]` | ScanDetail (policy tab) |
| `['policies']` | Policies |
| `['dashboard']` | Dashboard |
| `['audit-log']` | AuditLog |
| `['settings']` | Settings |
| `['registries']` | Registries |
| `['teams']` | Teams |
| `['team-dashboard', teamId]` | TeamDashboard |
| `['integrations']` | Integrations |
| `['integration-tickets', integrationId]` | Integrations (tickets section) |
| `['webhook-registration', integrationId]` | Integrations (webhook section) |
| `['webhook-events', integrationId]` | Integrations (webhook events) |
| `['automation-rules']` | AutomationRules |
| `['automation-triggers']` | AutomationRules, AutomationRuleEditor |
| `['automation-executions', ruleId]` | AutomationRules (execution history) |
| `['osv', vulnId]` | FindingCard (OsvDetailPanel) |

## HIGH-COMPLEXITY FILES

- `pages/Integrations.tsx` (~1070): Integration CRUD (Jira + GitHub Issues), ticket management, webhook registration, field mapping editor, ticket comments
- `pages/Registries.tsx` (~755): registry CRUD, repository browsing, auto-sync/auto-scan actions
- `pages/SeedScans.tsx` (~718): synthetic scan generation + progress orchestration
- `pages/Scans.tsx` (~626): table filters, create/delete/rerun flows, modal state
- `components/AutomationRuleEditor.tsx` (~630): trigger picker, condition builder, action builder, integration/team selectors
- `pages/ScanDetail.tsx` (~539): tabbed detail view, grouping/search, lazy tab fetches
- `pages/AutomationRules.tsx` (~500): rule table, create/edit modal with AutomationRuleEditor, execution history
- `pages/Workers.tsx` (~471): visual rack simulation + queue visualization + animations
- `components/FindingCard.tsx` (~320): collapsible finding + nested `OsvDetailPanel`
- `components/FieldMappingEditor.tsx` (~250): source→target mapping rows with transform options

## TYPES.TS INTERFACE INVENTORY

Core: `Scan`, `Finding`, `Policy`, `PolicyRule`, `DashboardData`, `SBOMComponent`, `SBOM`, `PolicyResult`, `AuditLogEntry`, `OsvVulnerability`, `OsvAffectedPackage`

Registry/Teams: `Registry`, `Team`, `OwnershipRule`, `TeamFindingSummary`, `TeamDashboardData`

Integrations: `Integration`, `IntegrationFieldMapping`, `Ticket`, `BulkCreateTicketsResponse`

Webhooks/Automation: `WebhookEvent`, `WebhookEventDetail`, `WebhookRegistration`, `TicketComment`, `AutomationRule`, `AutomationRuleExecution`

## FRONTEND-SPECIFIC GOTCHAS

- Backend sends naive UTC timestamps; always parse via `parseUTC()` (appends `"Z"`)
- No frontend test harness (no Vitest/Jest); verification is lint + build
- Keep all fetch/mutation logic in `api/*` + `useQuery`/`useMutation` wrappers
- `types.ts` owns domain shape; avoid local duplicate interfaces in page files
- `Integration.has_secret` is computed on the backend; never send `auth_secret` in reads

## ANTI-PATTERNS (THIS LAYER)

- No `as any`, `@ts-ignore`, `@ts-expect-error`
- No hardcoded hex colors in components; use CSS variables
- No direct axios calls inside JSX components when API wrapper exists
- No always-on polling for pages that can gate by scan status
- No heavy derived computations in render path without `useMemo`

## VERIFICATION

```bash
cd frontend && npm run lint && npm run build
```
