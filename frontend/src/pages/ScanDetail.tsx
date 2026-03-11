import { useState, useMemo } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, Package, ChevronDown, ChevronRight, Layers, RotateCcw, ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';
import { getScan, getFindings, rerunScan } from '../api/scans';
import { getSBOM } from '../api/sbom';
import { getPolicyResults } from '../api/policies';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';
import FindingCard from '../components/FindingCard';
import { formatDateTime } from '../utils';
import type { Finding } from '../types';

type Tab = 'findings' | 'sbom' | 'policy';
type SortField = 'severity' | 'cvss' | 'risk' | 'package' | 'vuln_id';
type SortDir = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NEGLIGIBLE: 4, UNKNOWN: 5 };

function topSeverity(findings: Finding[]): Finding['severity'] {
  return findings.reduce<Finding['severity']>((top, f) => {
    return (SEVERITY_ORDER[f.severity] ?? 5) < (SEVERITY_ORDER[top] ?? 5) ? f.severity : top;
  }, 'UNKNOWN');
}

interface CveGroupProps {
  vulnId: string;
  findings: Finding[];
}

function CveGroup({ vulnId, findings }: CveGroupProps) {
  const [open, setOpen] = useState(false);
  const severity = topSeverity(findings);
  const maxCvss = findings.reduce<number | null>((m, f) => {
    if (f.cvss_score === null) return m;
    return m === null || f.cvss_score > m ? f.cvss_score : m;
  }, null);

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 6, marginBottom: 8, background: 'var(--bg-card)' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%',
          display: 'grid',
          gridTemplateColumns: '1fr auto auto auto auto',
          alignItems: 'center',
          gap: 12,
          padding: '10px 14px',
          background: 'transparent',
          border: 'none',
          color: 'var(--text-primary)',
          cursor: 'pointer',
          textAlign: 'left',
        }}
      >
        <span style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 600 }}>{vulnId}</span>
        <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
          {findings.length} package{findings.length !== 1 ? 's' : ''} affected
        </span>
        <SeverityBadge severity={severity} />
        <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
          CVSS: {maxCvss !== null ? maxCvss.toFixed(1) : 'N/A'}
        </span>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {open && (
        <div style={{ padding: '8px 14px 14px', borderTop: '1px solid var(--border)' }}>
          {findings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sort button helper
// ---------------------------------------------------------------------------

interface SortBtnProps {
  field: SortField;
  label: string;
  current: SortField;
  dir: SortDir;
  onSort: (f: SortField) => void;
}

function SortBtn({ field, label, current, dir, onSort }: SortBtnProps) {
  const active = current === field;
  return (
    <button
      onClick={() => onSort(field)}
      style={{
        display: 'flex', alignItems: 'center', gap: 4,
        padding: '5px 10px', borderRadius: 4,
        border: '1px solid var(--border)',
        background: active ? 'rgba(59,130,246,0.12)' : 'transparent',
        color: active ? 'var(--accent)' : 'var(--text-secondary)',
        cursor: 'pointer', fontSize: 12, fontWeight: active ? 600 : 400,
        whiteSpace: 'nowrap',
      }}
    >
      {label}
      {active
        ? (dir === 'asc' ? <ArrowUp size={11} /> : <ArrowDown size={11} />)
        : <ArrowUpDown size={11} style={{ opacity: 0.4 }} />}
    </button>
  );
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>('findings');
  const [severityFilter, setSeverityFilter] = useState('');
  const [search, setSearch] = useState('');
  const [groupByCVE, setGroupByCVE] = useState(false);
  const [fixAvailableOnly, setFixAvailableOnly] = useState(false);
  const [exploitableOnly, setExploitableOnly] = useState(false);
  const [sortField, setSortField] = useState<SortField>('severity');
  const [sortDir, setSortDir] = useState<SortDir>('asc');
  const [rerunError, setRerunError] = useState('');

  const scanIsActive = (status?: string) => status === 'pending' || status === 'running';

  const { data: scan, isLoading: scanLoading, error: scanError } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => getScan(id!),
    enabled: !!id,
    refetchInterval: (query) => scanIsActive(query.state.data?.status) ? 2000 : false,
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => getFindings(id!),
    enabled: !!id,
    refetchInterval: (query) =>
      query.state.data !== undefined ? false : scanIsActive(scan?.status) ? 2000 : false,
  });

  const { data: sbom, isLoading: sbomLoading } = useQuery({
    queryKey: ['sbom', id],
    queryFn: () => getSBOM(id!),
    enabled: !!id && tab === 'sbom',
  });

  const { data: policyResults, isLoading: policyLoading } = useQuery({
    queryKey: ['policy-results', id],
    queryFn: () => getPolicyResults(id!),
    enabled: !!id && tab === 'policy',
  });

  const rerunMutation = useMutation({
    mutationFn: () => rerunScan(id!),
    onSuccess: (newScan) => {
      qc.invalidateQueries({ queryKey: ['scans'] });
      navigate(`/scans/${newScan.id}`);
    },
    onError: () => setRerunError('Failed to re-run scan. Please try again.'),
  });

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      // Default direction per field
      setSortDir(field === 'package' || field === 'vuln_id' ? 'asc' : 'desc');
    }
  }

  const filteredFindings = useMemo(() => {
    let result = (findings ?? []).filter((f: Finding) => {
      if (severityFilter && f.severity !== severityFilter) return false;
      if (search && !f.vulnerability_id.toLowerCase().includes(search.toLowerCase()) &&
          !f.package_name.toLowerCase().includes(search.toLowerCase())) return false;
      if (fixAvailableOnly && !f.is_fixed) return false;
      if (exploitableOnly && !f.exploitable) return false;
      return true;
    });

    result = [...result].sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'severity':
          cmp = (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5);
          break;
        case 'cvss':
          cmp = (a.cvss_score ?? -1) - (b.cvss_score ?? -1);
          break;
        case 'risk':
          cmp = (a.risk_score ?? 0) - (b.risk_score ?? 0);
          break;
        case 'package':
          cmp = a.package_name.localeCompare(b.package_name);
          break;
        case 'vuln_id':
          cmp = a.vulnerability_id.localeCompare(b.vulnerability_id);
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return result;
  }, [findings, severityFilter, search, fixAvailableOnly, exploitableOnly, sortField, sortDir]);

  const groupedByCVE = useMemo(() => {
    const map = new Map<string, Finding[]>();
    if (!groupByCVE) return map;
    for (const f of filteredFindings) {
      const group = map.get(f.vulnerability_id) ?? [];
      group.push(f);
      map.set(f.vulnerability_id, group);
    }
    return map;
  }, [groupByCVE, filteredFindings]);

  if (scanLoading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><span className="spinner" style={{ width: 32, height: 32 }} /></div>;
  if (scanError || !scan) return <div className="error-message">Failed to load scan.</div>;

  const tabStyle = (active: boolean): React.CSSProperties => ({
    padding: '10px 20px',
    background: 'transparent',
    border: 'none',
    borderBottom: active ? '2px solid var(--accent)' : '2px solid transparent',
    color: active ? 'var(--accent)' : 'var(--text-secondary)',
    cursor: 'pointer',
    fontWeight: active ? 600 : 400,
    fontSize: 14,
    marginBottom: -1,
  });

  const totalFindings = (findings ?? []).length;
  const activeFilters = severityFilter || search || fixAvailableOnly || exploitableOnly;

  return (
    <div>
      <div style={{ marginBottom: 20 }}>
        <Link to="/scans" style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)', fontSize: 13, marginBottom: 12 }}>
          <ArrowLeft size={14} /> Back to Scans
        </Link>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>{scan.target}</h1>
            <div style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
              {scan.scan_type} · {formatDateTime(scan.created_at)}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <StatusBadge status={scan.status} />
            {scan.scanner_engine && (
              <span style={{
                padding: '3px 9px', borderRadius: 4, fontSize: 11, fontWeight: 600,
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em',
              }}>
                {scan.scanner_engine}
              </span>
            )}
            {scan.scan_duration_seconds != null && (
              <span style={{
                padding: '3px 9px', borderRadius: 4, fontSize: 11,
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                color: 'var(--text-secondary)',
              }}>
                {scan.scan_duration_seconds < 60
                  ? `${Math.round(scan.scan_duration_seconds)}s`
                  : `${Math.floor(scan.scan_duration_seconds / 60)}m ${Math.round(scan.scan_duration_seconds % 60)}s`}
              </span>
            )}
            <Link to={`/sbom/${scan.id}`} style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '6px 12px', border: '1px solid var(--border)',
              borderRadius: 6, color: 'var(--text-secondary)', fontSize: 13,
            }}>
              <Package size={14} /> View SBOM
            </Link>
            <button
              onClick={() => { setRerunError(''); rerunMutation.mutate(); }}
              disabled={rerunMutation.isPending || scan.status === 'pending' || scan.status === 'running'}
              title="Re-run scan"
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 12px', border: '1px solid var(--border)',
                borderRadius: 6, color: 'var(--text-secondary)', fontSize: 13,
                background: 'transparent', cursor: 'pointer',
                opacity: (rerunMutation.isPending || scan.status === 'pending' || scan.status === 'running') ? 0.5 : 1,
              }}
            >
              <RotateCcw size={14} />
              {rerunMutation.isPending ? 'Queuing…' : 'Re-run'}
            </button>
          </div>
        </div>
        {rerunError && <div className="error-message" style={{ marginTop: 8 }}>{rerunError}</div>}
        {/* Unsupported / error reason banner */}
        {scan.error_message && (
          <div style={{
            marginTop: 10,
            padding: '10px 14px',
            borderRadius: 6,
            background: scan.status === 'unsupported' ? 'rgba(234,179,8,0.08)' : 'rgba(239,68,68,0.08)',
            border: `1px solid ${scan.status === 'unsupported' ? 'rgba(234,179,8,0.3)' : 'rgba(239,68,68,0.3)'}`,
            color: scan.status === 'unsupported' ? '#ca8a04' : 'var(--error)',
            fontSize: 13,
          }}>
            {scan.error_message}
          </div>
        )}
        {/* Base image (container scans only) */}
        {scan.scan_type === 'container' && scan.base_image && (
          <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)', fontSize: 12 }}>
            <Layers size={13} />
            <span>Base image: <code style={{ color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: 12 }}>{scan.base_image}</code></span>
            {scan.base_image_chain && scan.base_image_chain.length > 1 && (
              <span style={{ color: 'var(--text-secondary)' }}>
                ({scan.base_image_chain.join(' → ')})
              </span>
            )}
          </div>
        )}
        {/* Finding counts — clickable to filter */}
        <div style={{ display: 'flex', gap: 12, marginTop: 14 }}>
          {[
            { label: 'Critical',   key: 'CRITICAL',   count: scan.critical_count,   color: 'var(--critical)' },
            { label: 'High',       key: 'HIGH',       count: scan.high_count,       color: 'var(--high)' },
            { label: 'Medium',     key: 'MEDIUM',     count: scan.medium_count,     color: 'var(--medium)' },
            { label: 'Low',        key: 'LOW',        count: scan.low_count,        color: 'var(--low)' },
            { label: 'Negligible', key: 'NEGLIGIBLE', count: scan.negligible_count, color: 'var(--negligible)' },
            { label: 'Unknown',    key: 'UNKNOWN',    count: scan.unknown_count,    color: 'var(--unknown)' },
          ].map(({ label, key, count, color }) => {
            const active = severityFilter === key;
            return (
              <button
                key={label}
                onClick={() => {
                  setSeverityFilter(active ? '' : key);
                  setTab('findings');
                }}
                title={active ? `Remove ${label} filter` : `Filter by ${label}`}
                style={{
                  background: active ? `color-mix(in srgb, ${color} 15%, var(--bg-card))` : 'var(--bg-card)',
                  border: `1px solid ${active ? color : 'var(--border)'}`,
                  borderRadius: 6, padding: '8px 16px', textAlign: 'center',
                  cursor: 'pointer',
                  transition: 'border-color 0.15s, background 0.15s',
                  outline: 'none',
                }}
              >
                <div style={{ color, fontSize: 22, fontWeight: 700 }}>{count}</div>
                <div style={{ color: active ? color : 'var(--text-secondary)', fontSize: 11 }}>{label}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ borderBottom: '1px solid var(--border)', marginBottom: 20, display: 'flex' }}>
        <button style={tabStyle(tab === 'findings')} onClick={() => setTab('findings')}>
          Findings ({scan.findings_count})
        </button>
        <button style={tabStyle(tab === 'sbom')} onClick={() => setTab('sbom')}>SBOM</button>
        <button style={tabStyle(tab === 'policy')} onClick={() => setTab('policy')}>Policy Results</button>
      </div>

      {/* Findings Tab */}
      {tab === 'findings' && (
        <div>
          {scan.scanner_engine === 'syft+grype (windows)' && (
            <div style={{
              marginBottom: 16,
              padding: '10px 14px',
              borderRadius: 6,
              background: 'rgba(234,179,8,0.08)',
              border: '1px solid rgba(234,179,8,0.3)',
              color: '#ca8a04',
              fontSize: 13,
              lineHeight: 1.6,
            }}>
              <strong>Windows image — partial coverage.</strong> Grype detected language packages (.NET, Node, Java, Python, etc.) and binary CVEs (PE version matching). Windows OS KB patch-level CVEs are not included — the public Grype database does not contain MSRC data.
            </div>
          )}
          {/* Row 1: search + severity pills + group-by */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 10, flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search by vuln ID or package..."
              style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text-primary)', padding: '7px 12px', flex: 1, minWidth: 200 }}
            />
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {(['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN'] as const).map(s => (
                <button key={s} onClick={() => setSeverityFilter(s)} style={{
                  padding: '6px 12px', borderRadius: 4, border: '1px solid var(--border)',
                  background: severityFilter === s ? 'var(--accent)' : 'transparent',
                  color: severityFilter === s ? '#fff' : 'var(--text-secondary)',
                  cursor: 'pointer', fontSize: 12,
                }}>{s || 'All'}</button>
              ))}
            </div>
            <button
              onClick={() => setGroupByCVE(g => !g)}
              title="Toggle group by CVE"
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '6px 12px', borderRadius: 4, border: '1px solid var(--border)',
                background: groupByCVE ? 'var(--accent)' : 'transparent',
                color: groupByCVE ? '#fff' : 'var(--text-secondary)',
                cursor: 'pointer', fontSize: 12,
              }}
            >
              <Layers size={13} /> Group by CVE
            </button>
          </div>

          {/* Row 2: sort + toggle filters + result count */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: 12, marginRight: 2 }}>Sort:</span>
            <SortBtn field="severity" label="Severity"   current={sortField} dir={sortDir} onSort={handleSort} />
            <SortBtn field="cvss"     label="CVSS"       current={sortField} dir={sortDir} onSort={handleSort} />
            <SortBtn field="risk"     label="Risk Score" current={sortField} dir={sortDir} onSort={handleSort} />
            <SortBtn field="package"  label="Package"    current={sortField} dir={sortDir} onSort={handleSort} />
            <SortBtn field="vuln_id"  label="Vuln ID"    current={sortField} dir={sortDir} onSort={handleSort} />

            <div style={{ width: 1, height: 20, background: 'var(--border)', margin: '0 4px' }} />

            {/* Fix available toggle */}
            <button
              onClick={() => setFixAvailableOnly(v => !v)}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '5px 10px', borderRadius: 4, border: '1px solid var(--border)',
                background: fixAvailableOnly ? 'rgba(34,197,94,0.12)' : 'transparent',
                color: fixAvailableOnly ? 'var(--success)' : 'var(--text-secondary)',
                cursor: 'pointer', fontSize: 12, fontWeight: fixAvailableOnly ? 600 : 400,
              }}
            >
              ✓ Fix available
            </button>

            {/* Exploitable toggle */}
            <button
              onClick={() => setExploitableOnly(v => !v)}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '5px 10px', borderRadius: 4, border: '1px solid var(--border)',
                background: exploitableOnly ? 'rgba(239,68,68,0.12)' : 'transparent',
                color: exploitableOnly ? 'var(--critical)' : 'var(--text-secondary)',
                cursor: 'pointer', fontSize: 12, fontWeight: exploitableOnly ? 600 : 400,
              }}
            >
              ⚠ Exploitable
            </button>

            {/* Result count */}
            <span style={{ marginLeft: 'auto', color: 'var(--text-secondary)', fontSize: 12 }}>
              {activeFilters
                ? <>{filteredFindings.length} <span style={{ opacity: 0.6 }}>/ {totalFindings}</span> findings</>
                : <>{totalFindings} finding{totalFindings !== 1 ? 's' : ''}</>
              }
            </span>
          </div>

          {findingsLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><span className="spinner" /></div>
          ) : filteredFindings.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 40 }}>No findings match your filter.</p>
          ) : groupByCVE ? (
            Array.from(groupedByCVE.entries()).map(([vulnId, group]) => (
              <CveGroup key={vulnId} vulnId={vulnId} findings={group} />
            ))
          ) : (
            filteredFindings.map((f: Finding) => <FindingCard key={f.id} finding={f} />)
          )}
        </div>
      )}

      {/* SBOM Tab */}
      {tab === 'sbom' && (
        <div>
          {sbomLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><span className="spinner" /></div>
          ) : !sbom ? (
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 40 }}>No SBOM available for this scan.</p>
          ) : (
            <div>
              <p style={{ color: 'var(--text-secondary)', marginBottom: 14, fontSize: 13 }}>
                Format: {sbom.format} · {sbom.components.length} components · Generated: {formatDateTime(sbom.generated_at)}
              </p>
              <table>
                <thead><tr><th>Name</th><th>Version</th><th>Ecosystem</th><th>Licenses</th><th>PURL</th></tr></thead>
                <tbody>
                  {sbom.components.map((c, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 500 }}>{c.name}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{c.version}</td>
                      <td><span style={{ color: 'var(--text-secondary)' }}>{c.ecosystem}</span></td>
                      <td>{c.licenses.join(', ') || '—'}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-secondary)' }}>{c.purl ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Policy Results Tab */}
      {tab === 'policy' && (
        <div>
          {policyLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><span className="spinner" /></div>
          ) : !policyResults || policyResults.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 40 }}>No policy results available.</p>
          ) : (
            policyResults.map(pr => (
              <div key={pr.policy_id} style={{
                background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, padding: 16, marginBottom: 12,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <span style={{ fontWeight: 600 }}>{pr.policy_name}</span>
                  <span style={{
                    padding: '3px 10px', borderRadius: 4, fontSize: 12, fontWeight: 600,
                    background: pr.status === 'pass' ? 'rgba(34,197,94,0.15)' : pr.status === 'warn' ? 'rgba(234,179,8,0.15)' : 'rgba(239,68,68,0.15)',
                    color: pr.status === 'pass' ? 'var(--success)' : pr.status === 'warn' ? 'var(--warning)' : 'var(--error)',
                  }}>{pr.status.toUpperCase()}</span>
                </div>
                {pr.violations.length > 0 && (
                  <div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: 12, marginBottom: 6 }}>
                      {pr.violations.length} violation(s)
                    </div>
                    {pr.violations.map((v, i) => (
                      <div key={i} style={{
                        background: 'var(--bg-primary)', borderRadius: 4, padding: '6px 10px', marginBottom: 4, fontSize: 12,
                        border: '1px solid var(--border)',
                      }}>
                        <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{v.rule}</span>
                        <span style={{ color: 'var(--text-secondary)', marginLeft: 8 }}>— {v.message}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}
