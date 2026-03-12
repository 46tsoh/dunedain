import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate, Link } from 'react-router-dom';
import {
  Plus, X, ScanLine, Container, Trash2, RotateCcw,
  ChevronDown, ChevronRight, FileCode, FolderOpen, Search, Server, Users,
} from 'lucide-react';
import { getScans, createScan, deleteScan, rerunScan } from '../api/scans';
import { type Scan } from '../types';
import StatusBadge from '../components/StatusBadge';
import { formatDateTime } from '../utils';

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const overlayStyle: React.CSSProperties = {
  position: 'fixed', inset: 0,
  background: 'rgba(0,0,0,0.6)',
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  zIndex: 100,
};

const modalStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 10,
  padding: 24,
  width: 480,
  maxWidth: '95vw',
};

const inputStyle: React.CSSProperties = {
  background: 'var(--bg-primary)',
  border: '1px solid var(--border)',
  borderRadius: 4,
  color: 'var(--text-primary)',
  padding: '8px 12px',
  width: '100%',
  marginTop: 4,
};

const btnPrimary: React.CSSProperties = {
  background: 'var(--accent)',
  color: '#fff',
  border: 'none',
  borderRadius: 6,
  padding: '8px 16px',
  fontWeight: 600,
  cursor: 'pointer',
};

const iconBtn: React.CSSProperties = {
  background: 'transparent',
  border: 'none',
  color: 'var(--text-secondary)',
  cursor: 'pointer',
  padding: '4px',
  display: 'flex',
  alignItems: 'center',
};

// ---------------------------------------------------------------------------
// Engine label helpers
// ---------------------------------------------------------------------------

const OVERRIDE_LABEL: Record<string, string> = {
  trivy: 'trivy',
  grype: 'grype',
  syft_grype: 'syft+grype',
  osv_scanner: 'osv-scanner',
  auto: 'auto',
};

const WIN_MODE_LABEL: Record<string, string> = {
  layer_extraction: 'layer-extract',
  pe_version: 'pe-version',
};

const WIN_SCANNER_LABEL: Record<string, string> = {
  grype: 'grype',
  trivy: 'trivy',
};

function formatOverrideLabel(override: string): string {
  // "win:<mode>:<scanner>" — Windows override (current format)
  // "win:<mode>" — Windows override without scanner (transitional)
  if (override.startsWith('win:')) {
    const parts = override.slice(4).split(':');
    const mode = WIN_MODE_LABEL[parts[0]] ?? parts[0];
    const scanner = parts[1] ? (WIN_SCANNER_LABEL[parts[1]] ?? parts[1]) : null;
    return scanner ? `win/${mode} (${scanner})` : `win/${mode}`;
  }
  // "linux|win:<mode>" — legacy compound format still in DB
  const [linux, winPart] = override.split('|');
  if (winPart?.startsWith('win:')) {
    const mode = winPart.slice(4);
    return `win/${WIN_MODE_LABEL[mode] ?? mode}`;
  }
  return OVERRIDE_LABEL[linux] ?? linux;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

function effectiveEngine(scan: Scan): { label: string; pending: boolean } | null {
  if (scan.scanner_engine) return { label: scan.scanner_engine, pending: false };
  if (scan.scanner_override && (scan.status === 'pending' || scan.status === 'running')) {
    return { label: formatOverrideLabel(scan.scanner_override), pending: true };
  }
  return null;
}

const SCAN_TYPES = ['container', 'dependency', 'source'] as const;
type ScanType = typeof SCAN_TYPES[number];

const scanTypeLabel: Record<ScanType, string> = {
  container: 'Container',
  dependency: 'Dependency',
  source: 'Source',
};

const scanTypeTargetPlaceholder: Record<ScanType, string> = {
  container: 'e.g. nginx:1.21, python:3.12-slim, ubuntu:22.04',
  dependency: 'e.g. my-app-packages',
  source: 'e.g. /path/to/source or git URL',
};

const scanTypeTargetHelp: Record<ScanType, string | null> = {
  container: 'Enter a container image name with tag. Trivy + OSV will be used to detect vulnerabilities.',
  dependency: null,
  source: 'Provide a local directory path containing manifest files (requirements.txt, package.json, go.mod, etc.).',
};

const ScanTypeIcon = ({ type }: { type: string }) => {
  if (type === 'container') return <Container size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />;
  if (type === 'source') return <FolderOpen size={13} style={{ color: '#a78bfa', flexShrink: 0 }} />;
  return <FileCode size={13} style={{ color: '#34d399', flexShrink: 0 }} />;
};

// ---------------------------------------------------------------------------
// Severity pill row
// ---------------------------------------------------------------------------

function SeverityPills({ scan }: { scan: Scan }) {
  const pills = [
    { label: 'C', count: scan.critical_count,   color: 'var(--critical)' },
    { label: 'H', count: scan.high_count,        color: 'var(--high)' },
    { label: 'M', count: scan.medium_count,      color: 'var(--medium)' },
    { label: 'L', count: scan.low_count,         color: 'var(--low)' },
    { label: 'N', count: scan.negligible_count,  color: 'var(--negligible)' },
    { label: 'U', count: scan.unknown_count,      color: 'var(--unknown)' },
  ];
  return (
    <div style={{ display: 'flex', gap: 12, flexShrink: 0 }}>
      {pills.map(({ label, count, color }) => (
        <div key={label} style={{ textAlign: 'center', minWidth: 22 }}>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', lineHeight: 1.2 }}>{label}</div>
          <div style={{ fontWeight: 700, color, fontSize: 14, lineHeight: 1.3 }}>{count ?? '—'}</div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Individual scan sub-row (used for ALL runs, including the latest)
// ---------------------------------------------------------------------------

interface ScanRowProps {
  scan: Scan;
  onRerun: (id: string) => void;
  onDelete: (id: string) => void;
  rerunPending: boolean;
  isLatest?: boolean;
  showTag?: boolean;
}

function ScanRow({ scan, onRerun, onDelete, rerunPending, isLatest, showTag }: ScanRowProps) {
  const navigate = useNavigate();
  // Extract just the tag from the full target URL for registry scans
  const tagLabel = showTag ? (() => {
    const withoutHost = scan.target.replace(/^[^/]+\//, '');
    return withoutHost.includes(':') ? withoutHost.split(':')[1] : withoutHost;
  })() : null;
  return (
    <div
      onClick={() => navigate(`/scans/${scan.id}`)}
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '11px 20px 11px 44px',
        borderTop: '1px solid var(--border)',
        gap: 12,
        background: isLatest ? 'rgba(255,255,255,0.02)' : 'transparent',
        cursor: 'pointer',
      }}
      onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.04)')}
      onMouseLeave={e => (e.currentTarget.style.background = isLatest ? 'rgba(255,255,255,0.02)' : 'transparent')}
    >
      <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span title={scan.error_message ?? undefined}>
          <StatusBadge status={scan.status} />
        </span>
        <span style={{ fontSize: 13, color: isLatest ? 'var(--text-primary)' : 'var(--text-secondary)', fontWeight: isLatest ? 600 : 400 }}>
          {formatDateTime(scan.created_at)}
        </span>
        {tagLabel && (
          <span style={{ fontSize: 11, padding: '1px 7px', borderRadius: 4, background: 'rgba(99,102,241,0.12)', color: '#818cf8', border: '1px solid rgba(99,102,241,0.3)', fontFamily: 'monospace' }}>
            {tagLabel}
          </span>
        )}
        {isLatest && <span style={{ fontSize: 10, color: 'var(--accent)', opacity: 0.8 }}>latest</span>}
        {(() => {
          const eng = effectiveEngine(scan);
          if (!eng) return null;
          return (
            <span style={{ fontSize: 11, color: 'var(--text-secondary)', opacity: eng.pending ? 0.4 : 0.55, fontStyle: eng.pending ? 'italic' : 'normal' }}>
              {eng.label}{eng.pending ? '…' : ''}
            </span>
          );
        })()}
        {scan.scan_duration_seconds != null && (
          <span style={{ fontSize: 11, color: 'var(--text-secondary)', opacity: 0.45 }}>
            {formatDuration(scan.scan_duration_seconds)}
          </span>
        )}
      </div>
      <SeverityPills scan={scan} />
      <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
        <button
          onClick={e => { e.stopPropagation(); onRerun(scan.id); }}
          disabled={rerunPending || scan.status === 'pending' || scan.status === 'running'}
          title="Re-run"
          style={{ ...iconBtn, opacity: (rerunPending || scan.status === 'pending' || scan.status === 'running') ? 0.4 : 1 }}
        >
          <RotateCcw size={13} />
        </button>
        <button onClick={e => { e.stopPropagation(); onDelete(scan.id); }} title="Delete" style={iconBtn}>
          <Trash2 size={13} />
        </button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Grouped card — header is the target, all scans are sub-rows
// ---------------------------------------------------------------------------

interface ScanGroup {
  key: string;
  name: string;
  target: string;
  scan_type: string;
  registry_name: string | null;
  scans: Scan[];   // all runs, newest first
}

interface GroupCardProps {
  group: ScanGroup;
  onRerun: (id: string) => void;
  onDelete: (id: string) => void;
  rerunPending: boolean;
}

function GroupCard({ group, onRerun, onDelete, rerunPending }: GroupCardProps) {
  const [collapsed, setCollapsed] = useState(group.scans.length > 1);
  const latest    = group.scans[0];
  const baseImage = group.scans.find(s => s.base_image)?.base_image ?? null;
  const teamName  = latest.team_name ?? null;
  const teamId    = latest.team_id ?? null;
  const hasMany   = group.scans.length > 1;
  const visible   = collapsed ? [latest] : group.scans;

  // For registry-sourced scans use the stored name (repo without host/tag).
  // For everything else strip the hostname as before.
  const displayTarget = (() => {
    if (group.registry_name) return group.name;
    return group.target;
  })();

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      marginBottom: 10,
      overflow: 'hidden',
    }}>
      {/* Group header — target identity only, no scan data */}
      <div
        onClick={() => hasMany && setCollapsed(x => !x)}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 20px', gap: 12,
          borderBottom: '1px solid var(--border)',
          cursor: hasMany ? 'pointer' : 'default',
          userSelect: 'none',
        }}
        onMouseEnter={e => { if (hasMany) e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; }}
        onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 0 }}>
          {/* Collapse indicator */}
          <span style={{ width: 18, flexShrink: 0, display: 'flex', alignItems: 'center', color: 'var(--text-secondary)' }}>
            {hasMany && (collapsed ? <ChevronRight size={14} /> : <ChevronDown size={14} />)}
          </span>

          <ScanTypeIcon type={group.scan_type} />

          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <span style={{ fontWeight: 600, fontSize: 15 }}>{displayTarget}</span>
              {group.registry_name && (
                <span style={{
                  fontSize: 10, padding: '1px 6px', borderRadius: 4,
                  background: 'rgba(167,139,250,0.12)', color: '#a78bfa',
                  border: '1px solid rgba(167,139,250,0.3)',
                  display: 'flex', alignItems: 'center', gap: 3,
                  flexShrink: 0,
                }}>
                  <Server size={9} />
                  {group.registry_name}
                </span>
              )}
              {teamName && teamId && (
                <Link
                  to={`/teams/${teamId}/dashboard`}
                  onClick={e => e.stopPropagation()}
                  style={{
                    fontSize: 10, padding: '1px 6px', borderRadius: 4,
                    background: 'rgba(99,102,241,0.12)', color: '#818cf8',
                    border: '1px solid rgba(99,102,241,0.3)',
                    display: 'flex', alignItems: 'center', gap: 3,
                    flexShrink: 0,
                    textDecoration: 'none',
                  }}
                >
                  <Users size={9} />
                  {teamName}
                </Link>
              )}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 1, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {baseImage && <span>base: {baseImage}</span>}
            </div>
          </div>
        </div>

        {/* Right: run count */}
        {hasMany && (
          <span style={{ color: 'var(--text-secondary)', fontSize: 12, flexShrink: 0 }}>
            {group.scans.length} runs
          </span>
        )}
      </div>

      {/* Scan sub-rows */}
      {visible.map((scan, i) => (
        <ScanRow
          key={scan.id}
          scan={scan}
          onRerun={onRerun}
          onDelete={onDelete}
          rerunPending={rerunPending}
          isLatest={i === 0 && hasMany}
          showTag={!!group.registry_name}
        />
      ))}

      {/* "Show N more" footer when collapsed */}
      {collapsed && group.scans.length > 1 && (
        <button
          onClick={() => setCollapsed(false)}
          style={{
            width: '100%', background: 'none', border: 'none',
            borderTop: '1px solid var(--border)',
            color: 'var(--text-secondary)', fontSize: 12,
            padding: '7px 0', cursor: 'pointer',
          }}
        >
          + {group.scans.length - 1} older {group.scans.length - 1 === 1 ? 'run' : 'runs'}
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Group scans by (target + scan_type), newest first within each group
// ---------------------------------------------------------------------------

function groupScans(scans: Scan[]): ScanGroup[] {
  const map = new Map<string, Scan[]>();

  for (const scan of scans) {
    let key: string;
    if (scan.registry_id) {
      // For registry scans group by repo (strip the tag) so all tags of the
      // same repo collapse into one card
      const withoutHost = scan.target.replace(/^[^/]+\//, ''); // strip registry hostname
      const repo = withoutHost.includes(':') ? withoutHost.split(':')[0] : withoutHost;
      key = `${scan.scan_type}::registry::${scan.registry_id}::${repo}`;
    } else {
      key = `${scan.scan_type}::${scan.target}`;
    }
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push(scan);
  }

  const groups: ScanGroup[] = [];
  for (const [key, items] of map) {
    const sorted = [...items].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
    groups.push({
      key,
      name: sorted[0].target,
      target: sorted[0].target,
      scan_type: sorted[0].scan_type,
      registry_name: sorted[0].registry_name ?? null,
      scans: sorted,
    });
  }

  // Sort groups: those with active scans first, then by latest scan date
  groups.sort((a, b) => {
    const aActive = a.scans[0].status === 'pending' || a.scans[0].status === 'running' ? 1 : 0;
    const bActive = b.scans[0].status === 'pending' || b.scans[0].status === 'running' ? 1 : 0;
    if (aActive !== bActive) return bActive - aActive;
    return new Date(b.scans[0].created_at).getTime() - new Date(a.scans[0].created_at).getTime();
  });

  return groups;
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Scans() {
  const [showModal, setShowModal]     = useState(false);
  const [search, setSearch]           = useState('');
  const [typeFilter, setTypeFilter]   = useState('');
  const [form, setForm] = useState({
    scan_type: 'container' as string, target: '', packages: '',
  });
  const [formError, setFormError]     = useState('');
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState('');

  const qc = useQueryClient();

  const { data: scans, isLoading, error } = useQuery({
    queryKey: ['scans', typeFilter],
    queryFn: () => getScans(typeFilter || undefined),
    refetchInterval: (query) => {
      const data = query.state.data as Scan[] | undefined;
      return data?.some(s => s.status === 'pending' || s.status === 'running') ? 3000 : false;
    },
  });

  const mutation = useMutation({
    mutationFn: createScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: () => setFormError('Failed to queue scan. Please try again or check server logs.'),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteScan,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      setConfirmDeleteId(null);
    },
    onError: () => setDeleteError('Failed to delete scan. Please try again.'),
  });

  const rerunMutation = useMutation({
    mutationFn: rerunScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    let packages: Array<{ name: string; version: string; ecosystem: string }> | undefined;
    if (form.packages.trim()) {
      try { packages = JSON.parse(form.packages); }
      catch { setFormError('Packages must be valid JSON array'); return; }
    }
    mutation.mutate({ scan_type: form.scan_type, target: form.target, packages });
    setShowModal(false);
    setForm({ scan_type: 'container', target: '', packages: '' });
  };

  const isContainerForm  = form.scan_type === 'container';
  const currentScanType  = form.scan_type as ScanType;
  const allGroups        = scans ? groupScans(scans) : [];
  const groups           = allGroups.filter(g =>
    !search || g.target.toLowerCase().includes(search.toLowerCase()) || g.name.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700 }}>Scans</h1>
        <button onClick={() => setShowModal(true)} style={{ ...btnPrimary, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Plus size={16} /> New Scan
        </button>
      </div>

      {/* Filters */}
      <div style={{ marginBottom: 16, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        {/* Search box */}
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <Search size={13} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)', pointerEvents: 'none' }} />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter by target…"
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              color: 'var(--text-primary)',
              padding: '5px 10px 5px 28px',
              fontSize: 13,
              width: 200,
              outline: 'none',
            }}
          />
        </div>

        {/* Type pills */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {(['', ...SCAN_TYPES] as const).map(t => (
            <button key={t} onClick={() => setTypeFilter(t)} style={{
              padding: '4px 12px', borderRadius: 20, border: '1px solid var(--border)',
              background: typeFilter === t ? 'var(--accent)' : 'transparent',
              color: typeFilter === t ? '#fff' : 'var(--text-secondary)',
              cursor: 'pointer', fontSize: 12,
            }}>
              {t ? scanTypeLabel[t as ScanType] : 'All'}
            </button>
          ))}
        </div>
      </div>

      {/* Summary line */}
      {scans && scans.length > 0 && (
        <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 14 }}>
          {groups.length} {groups.length === 1 ? 'target' : 'targets'}
          {search && ` matching "${search}"`}
          {' · '}
          {scans.filter(s => s.status === 'pending' || s.status === 'running').length > 0 && (
            <span style={{ color: 'var(--accent)' }}>
              {scans.filter(s => s.status === 'pending' || s.status === 'running').length} scanning
              {' · '}
            </span>
          )}
          {scans.filter(s => s.status === 'completed').length} completed
        </div>
      )}

      {isLoading && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
          <span className="spinner" />
        </div>
      )}
      {error && <div className="error-message">Failed to load scans.</div>}

      {scans && scans.length === 0 && (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-secondary)' }}>
          <ScanLine size={48} style={{ marginBottom: 12, opacity: 0.3 }} />
          <p>No scans yet. Click "New Scan" to get started.</p>
        </div>
      )}

      {/* Grouped cards */}
      {groups.map(group => (
        <GroupCard
          key={group.key}
          group={group}
          onRerun={id => rerunMutation.mutate(id)}
          onDelete={id => setConfirmDeleteId(id)}
          rerunPending={rerunMutation.isPending}
        />
      ))}

      {/* ---- New Scan Modal ---- */}
      {showModal && (
        <div style={overlayStyle} onClick={() => setShowModal(false)}>
          <div style={modalStyle} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700 }}>New Scan</h2>
              <button onClick={() => setShowModal(false)} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>
            {formError && <div className="error-message" style={{ marginBottom: 16 }}>{formError}</div>}
            <form onSubmit={handleSubmit}>
              <div style={{ marginBottom: 14 }}>
                <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Scan Type *</label>
                <select value={form.scan_type} onChange={e => setForm(f => ({ ...f, scan_type: e.target.value, packages: '' }))}
                  style={inputStyle}>
                  {SCAN_TYPES.map(t => (
                    <option key={t} value={t}>{scanTypeLabel[t]}</option>
                  ))}
                </select>
              </div>
              <div style={{ marginBottom: isContainerForm ? 20 : 14 }}>
                <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                  {isContainerForm ? 'Image Name *' : 'Target *'}
                </label>
                <input required value={form.target} onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
                  style={inputStyle} placeholder={scanTypeTargetPlaceholder[currentScanType]} />
                {scanTypeTargetHelp[currentScanType] && (
                  <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                    {scanTypeTargetHelp[currentScanType]}
                  </p>
                )}
              </div>
              {!isContainerForm && (
                <div style={{ marginBottom: 20 }}>
                  <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Packages (JSON array, optional)</label>
                  <textarea value={form.packages} onChange={e => setForm(f => ({ ...f, packages: e.target.value }))}
                    style={{ ...inputStyle, height: 80, resize: 'vertical' }}
                    placeholder='[{"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}]' />
                </div>
              )}
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => setShowModal(false)} style={{
                  background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)',
                  borderRadius: 6, padding: '8px 16px', cursor: 'pointer',
                }}>Cancel</button>
                <button type="submit" style={btnPrimary} disabled={mutation.isPending}>
                  {isContainerForm ? 'Scan Image' : 'Start Scan'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ---- Delete Confirmation Modal ---- */}
      {confirmDeleteId && (
        <div style={overlayStyle} onClick={() => { setConfirmDeleteId(null); setDeleteError(''); }}>
          <div style={{ ...modalStyle, width: 360 }} onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 12 }}>Delete Scan</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
              Are you sure you want to delete this scan? This will also remove all findings, SBOM data, and policy results associated with it.
            </p>
            {deleteError && <div className="error-message" style={{ marginBottom: 16 }}>{deleteError}</div>}
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button type="button" onClick={() => { setConfirmDeleteId(null); setDeleteError(''); }}
                style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, padding: '8px 16px', cursor: 'pointer' }}>
                Cancel
              </button>
              <button type="button" onClick={() => deleteMutation.mutate(confirmDeleteId!)}
                disabled={deleteMutation.isPending}
                style={{ background: 'var(--critical)', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 16px', fontWeight: 600, cursor: 'pointer' }}>
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
