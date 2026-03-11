import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getAuditLog } from '../api/reports';
import { formatDateTime } from '../utils';

const ACTION_OPTIONS = [
  'scan_completed',
  'scan_created',
  'policy_created',
  'policy_updated',
  'policy_deleted',
  'sbom_ingested',
];

const RESOURCE_OPTIONS = ['scan', 'policy', 'sbom', 'finding'];

const ACTION_COLORS: Record<string, { bg: string; fg: string }> = {
  scan_completed: { bg: 'rgba(34,197,94,0.12)',  fg: 'var(--success)' },
  scan_created:   { bg: 'rgba(59,130,246,0.12)', fg: 'var(--accent)'  },
  policy_created: { bg: 'rgba(59,130,246,0.12)', fg: 'var(--accent)'  },
  policy_updated: { bg: 'rgba(234,179,8,0.12)',  fg: 'var(--warning)' },
  policy_deleted: { bg: 'rgba(239,68,68,0.12)',  fg: 'var(--error)'   },
  sbom_ingested:  { bg: 'rgba(168,85,247,0.12)', fg: '#a855f7'        },
};

const PAGE_SIZE = 50;

export default function AuditLog() {
  const [actionFilter, setActionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');
  const [page, setPage] = useState(0);

  const { data: entries, isLoading, isError } = useQuery({
    queryKey: ['audit-log', actionFilter, resourceFilter, page],
    queryFn: () => getAuditLog({
      action: actionFilter || undefined,
      resource_type: resourceFilter || undefined,
      limit: PAGE_SIZE,
      skip: page * PAGE_SIZE,
    }),
  });

  const filterStyle: React.CSSProperties = {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    color: 'var(--text-primary)',
    padding: '6px 10px',
    fontSize: 13,
    cursor: 'pointer',
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
          Audit Log
        </h1>
        {/* Filters */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select
            value={actionFilter}
            onChange={e => { setActionFilter(e.target.value); setPage(0); }}
            style={filterStyle}
          >
            <option value="">All actions</option>
            {ACTION_OPTIONS.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
          <select
            value={resourceFilter}
            onChange={e => { setResourceFilter(e.target.value); setPage(0); }}
            style={filterStyle}
          >
            <option value="">All resources</option>
            {RESOURCE_OPTIONS.map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          {(actionFilter || resourceFilter) && (
            <button
              onClick={() => { setActionFilter(''); setResourceFilter(''); setPage(0); }}
              style={{ ...filterStyle, color: 'var(--text-secondary)', cursor: 'pointer' }}
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {isLoading && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
          <span className="spinner" />
        </div>
      )}

      {isError && (
        <div style={{
          background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 8, padding: '12px 16px', color: '#ef4444',
        }}>
          Failed to load audit log.
        </div>
      )}

      {!isLoading && !isError && entries?.length === 0 && (
        <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 60 }}>
          No audit log entries{actionFilter || resourceFilter ? ' matching the current filters' : ' yet'}.
        </p>
      )}

      {entries && entries.length > 0 && (
        <>
          <div style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 8,
            overflow: 'hidden',
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)' }}>
                  {['Timestamp', 'Action', 'Resource Type', 'Resource ID', 'Details'].map(h => (
                    <th key={h} style={{
                      padding: '10px 14px', textAlign: 'left',
                      fontSize: 12, fontWeight: 600,
                      color: 'var(--text-secondary)',
                      background: 'var(--bg-primary)',
                      whiteSpace: 'nowrap',
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entries.map((entry, i) => {
                  const colors = ACTION_COLORS[entry.action] ?? { bg: 'rgba(100,100,100,0.1)', fg: 'var(--text-secondary)' };
                  return (
                    <tr key={entry.id} style={{
                      borderBottom: i < entries.length - 1 ? '1px solid var(--border)' : 'none',
                    }}>
                      <td style={{ padding: '10px 14px', color: 'var(--text-secondary)', fontSize: 12, whiteSpace: 'nowrap' }}>
                        {formatDateTime(entry.created_at)}
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <span style={{
                          fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                          background: colors.bg, color: colors.fg,
                          whiteSpace: 'nowrap',
                        }}>
                          {entry.action}
                        </span>
                      </td>
                      <td style={{ padding: '10px 14px', color: 'var(--text-secondary)', fontSize: 13 }}>
                        {entry.resource_type}
                      </td>
                      <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontSize: 11, color: 'var(--text-secondary)' }}>
                        {entry.resource_id
                          ? <span title={entry.resource_id}>{entry.resource_id.slice(0, 8)}…</span>
                          : <span style={{ opacity: 0.4 }}>—</span>
                        }
                      </td>
                      <td style={{ padding: '10px 14px', fontSize: 12, color: 'var(--text-secondary)', maxWidth: 280 }}>
                        <span
                          title={JSON.stringify(entry.details, null, 2)}
                          style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                        >
                          {Object.entries(entry.details).map(([k, v]) => `${k}: ${v}`).join(', ') || '—'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 10, marginTop: 14 }}>
            <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
              Showing {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + entries.length}
            </span>
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              style={{ ...filterStyle, opacity: page === 0 ? 0.4 : 1 }}
            >
              Previous
            </button>
            <button
              onClick={() => setPage(p => p + 1)}
              disabled={entries.length < PAGE_SIZE}
              style={{ ...filterStyle, opacity: entries.length < PAGE_SIZE ? 0.4 : 1 }}
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}
