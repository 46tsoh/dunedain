# frontend/src — Frontend Application Layer

## OVERVIEW

React 19 + TypeScript + Vite SPA. Data flow via TanStack Query v5 + typed API clients. Styling is inline style objects + CSS variables from `index.css`.

## STRUCTURE

```
src/
├── App.tsx               # QueryClient setup + route tree
├── main.tsx              # React root mount
├── types.ts              # Shared domain interfaces (single source of truth)
├── utils.ts              # Helpers (`parseUTC`, formatting)
├── api/                  # Axios client + domain API wrappers
├── components/           # Reusable UI blocks (cards, badges, editors, layout)
├── pages/                # Route-level screens
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

## ROUTING MAP

- `/dashboard` → `pages/Dashboard.tsx`
- `/scans` → `pages/Scans.tsx`
- `/scans/:id` → `pages/ScanDetail.tsx`
- `/policies` → `pages/Policies.tsx`
- `/sbom/:scanId` → `pages/SBOMViewer.tsx`
- `/audit-log` → `pages/AuditLog.tsx`
- `/settings` → `pages/Settings.tsx`
- `/workers` → `pages/Workers.tsx`
- `/registries` → `pages/Registries.tsx`
- `/seed-scans` → `pages/SeedScans.tsx`

## QUERY / POLLING CONTRACT

- Global QueryClient defaults (`App.tsx`): `retry: 1`, `refetchOnWindowFocus: false`
- `Scans.tsx`: poll every 3000ms only while any scan is `pending`/`running`
- `ScanDetail.tsx`: poll every 2000ms while current scan active
- `Workers.tsx`: poll every 1500ms (unconditional rack view)
- OSV deep-dive (`FindingCard.tsx`): `staleTime: 5 * 60 * 1000`

## HIGH-COMPLEXITY FILES

- `pages/Registries.tsx` (~755): registry CRUD, repository browsing, auto-sync/auto-scan actions
- `pages/SeedScans.tsx` (~718): synthetic scan generation + progress orchestration
- `pages/Scans.tsx` (~626): table filters, create/delete/rerun flows, modal state
- `pages/ScanDetail.tsx` (~539): tabbed detail view, grouping/search, lazy tab fetches
- `pages/Workers.tsx` (~471): visual rack simulation + queue visualization + animations
- `components/FindingCard.tsx` (~320): collapsible finding + nested `OsvDetailPanel`

## FRONTEND-SPECIFIC GOTCHAS

- Backend sends naive UTC timestamps; always parse via `parseUTC()` (appends `"Z"`)
- No frontend test harness (no Vitest/Jest); verification is lint + build
- Keep all fetch/mutation logic in `api/*` + `useQuery`/`useMutation` wrappers
- `types.ts` owns domain shape; avoid local duplicate interfaces in page files

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
