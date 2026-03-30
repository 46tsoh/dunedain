import { useState, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { AlertTriangle, Clock, CheckCircle, XCircle, ArrowLeft, Shield, Activity } from 'lucide-react';
import { getTeamDashboard } from '../api/teams';
import { getSettings } from '../api/settings';
import SeverityBadge from '../components/SeverityBadge';
import { formatDateTime } from '../utils';
import type { TeamFindingSummary } from '../types';

const sevOrder: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NEGLIGIBLE: 0, UNKNOWN: -1 };

const card = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  padding: '20px 24px',
};

const filterBtn = (active: boolean) => ({
  background: active ? 'var(--accent)' : 'var(--bg-primary)',
  color: active ? '#fff' : 'var(--text-secondary)',
  border: '1px solid ' + (active ? 'var(--accent)' : 'var(--border)'),
  borderRadius: 6,
  padding: '6px 12px',
  cursor: 'pointer',
  fontSize: 12,
  fontWeight: active ? 600 : 400,
});

const inputStyle = {
  background: 'var(--bg-primary)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: '6px 10px',
  color: 'var(--text-primary)',
  fontSize: 12,
};

function formatHours(hours: number): string {
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 24) return `${Math.round(hours)}h`;
  const days = Math.floor(hours / 24);
  const rem = Math.round(hours % 24);
  return rem > 0 ? `${days}d ${rem}h` : `${days}d`;
}

function slaProgressBar(finding: TeamFindingSummary) {
  if (finding.sla_hours == null) return null;
  const pct = Math.min((finding.hours_elapsed / finding.sla_hours) * 100, 100);
  const color = finding.sla_violated ? 'var(--error)' : pct > 75 ? 'var(--warning)' : 'var(--success)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, background: 'var(--bg-primary)', borderRadius: 3, overflow: 'hidden', minWidth: 60 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontSize: 11, color, fontWeight: 600, whiteSpace: 'nowrap' }}>
        {formatHours(finding.hours_elapsed)} / {formatHours(finding.sla_hours)}
      </span>
    </div>
  );
}

export default function TeamDashboard() {
  const { teamId } = useParams<{ teamId: string }>();
  const [severity, setSeverity] = useState<string>('');
  const [slaStatus, setSlaStatus] = useState<string>('');
  const [fixedFilter, setFixedFilter] = useState<string>('');
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState<'hours_elapsed' | 'risk_score' | 'severity' | 'discovered_at'>('hours_elapsed');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');

  const { data, isLoading, error } = useQuery({
    queryKey: ['team-dashboard', teamId, severity, slaStatus, fixedFilter],
    queryFn: () => getTeamDashboard(teamId!, {
      severity: severity || undefined,
      sla_status: slaStatus || undefined,
      is_fixed: fixedFilter === '' ? undefined : fixedFilter === 'true',
    }),
    enabled: !!teamId,
  });

  const { data: settings } = useQuery({
    queryKey: ['settings'],
    queryFn: getSettings,
  });

  const filteredFindings = useMemo(() => {
    if (!data) return [];
    let list = data.findings;
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(f =>
        f.vulnerability_id.toLowerCase().includes(q) ||
        f.package_name.toLowerCase().includes(q) ||
        f.scan_name.toLowerCase().includes(q)
      );
    }
    list = [...list].sort((a, b) => {
      let cmp = 0;
      if (sortField === 'hours_elapsed') cmp = a.hours_elapsed - b.hours_elapsed;
      else if (sortField === 'risk_score') cmp = a.risk_score - b.risk_score;
      else if (sortField === 'severity') cmp = (sevOrder[a.severity] ?? -1) - (sevOrder[b.severity] ?? -1);
      else if (sortField === 'discovered_at') cmp = new Date(a.discovered_at).getTime() - new Date(b.discovered_at).getTime();
      return sortDir === 'desc' ? -cmp : cmp;
    });
    return list;
  }, [data, search, sortField, sortDir]);

  function toggleSort(field: typeof sortField) {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDir('desc'); }
  }

  if (isLoading) return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}>
      <span className="spinner" style={{ width: 32, height: 32 }} />
    </div>
  );

  if (error || !data) return <div className="error-message">Failed to load team dashboard.</div>;

  const chartData = [
    { name: 'Critical', value: data.critical_count, color: '#ef4444' },
    { name: 'High',     value: data.high_count,     color: '#f97316' },
    { name: 'Medium',   value: data.medium_count,   color: '#eab308' },
    { name: 'Low',      value: data.low_count,       color: '#22c55e' },
  ];

  const team = data.team;

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
        <Link to="/teams" style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center' }}>
          <ArrowLeft size={20} />
        </Link>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700 }}>{team.name}</h1>
          {team.description && <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 2 }}>{team.description}</p>}
        </div>
      </div>

      {/* Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Unique Vulnerabilities', value: data.total_findings, icon: Activity, color: 'var(--text-secondary)' },
          { label: 'Critical', value: data.critical_count, icon: AlertTriangle, color: 'var(--critical)' },
          { label: 'High', value: data.high_count, icon: Shield, color: 'var(--high)' },
          { label: 'SLA Violations', value: data.sla_violations, icon: XCircle, color: 'var(--error)' },
          { label: 'Scans', value: team.scan_count, icon: CheckCircle, color: 'var(--accent)' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ color: 'var(--text-secondary)', fontSize: 12, marginBottom: 6 }}>{label}</div>
                <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
              </div>
              <Icon size={18} color={color} />
            </div>
          </div>
        ))}
      </div>

      {/* SLA Config Summary + Chart */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        <div style={card}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData}>
              <XAxis dataKey="name" stroke="var(--text-secondary)" tick={{ fontSize: 12 }} />
              <YAxis stroke="var(--text-secondary)" tick={{ fontSize: 12 }} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6 }}
                labelStyle={{ color: 'var(--text-primary)', fontWeight: 600 }}
                itemStyle={{ color: 'var(--text-primary)' }}
                cursor={{ fill: 'rgba(255,255,255,0.05)' }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {chartData.map(entry => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div style={card}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Clock size={16} /> SLA Configuration
          </h2>
          {(() => {
            const settingVal = (key: string, fallback: string) =>
              settings?.find(s => s.key === key)?.value ?? fallback;
            const mode = settingVal('sla_mode', 'severity');
            const critH = settingVal('sla_critical_hours', '24');
            const highH = settingVal('sla_high_hours', '72');
            const medH = settingVal('sla_medium_hours', '168');
            const lowH = settingVal('sla_low_hours', '720');
            const cvssC = settingVal('sla_cvss_critical_min', '9.0');
            const cvssH = settingVal('sla_cvss_high_min', '7.0');
            const cvssM = settingVal('sla_cvss_medium_min', '4.0');
            const tiers = mode === 'cvss'
              ? [
                  { label: `CVSS >= ${cvssC}`, hours: critH, color: 'var(--critical)' },
                  { label: `CVSS >= ${cvssH}`, hours: highH, color: 'var(--high)' },
                  { label: `CVSS >= ${cvssM}`, hours: medH, color: 'var(--medium)' },
                  { label: `CVSS < ${cvssM}`, hours: lowH, color: 'var(--low)' },
                ]
              : [
                  { label: 'Critical', hours: critH, color: 'var(--critical)' },
                  { label: 'High', hours: highH, color: 'var(--high)' },
                  { label: 'Medium', hours: medH, color: 'var(--medium)' },
                  { label: 'Low', hours: lowH, color: 'var(--low)' },
                ];
            return (
              <div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>
                  Mode: <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{mode === 'cvss' ? 'CVSS Score' : 'Severity'}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {tiers.map(({ label, hours, color }) => (
                    <div key={label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ color, fontWeight: 600, fontSize: 13 }}>{label}</span>
                      <span style={{ color: 'var(--text-primary)', fontSize: 13 }}>{hours ? formatHours(Number(hours)) : 'Not set'}</span>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 12 }}>
                  <Link to="/settings" style={{ color: 'var(--accent)', fontSize: 12 }}>Configure in Settings</Link>
                </div>
              </div>
            );
          })()}
        </div>
      </div>

      {/* Filters */}
      <div style={{ ...card, marginBottom: 16 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600 }}>Severity:</span>
          {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
            <button key={s} style={filterBtn(severity === s)} onClick={() => setSeverity(s)}>
              {s || 'All'}
            </button>
          ))}
          <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, marginLeft: 12 }}>SLA:</span>
          {['', 'violated', 'ok'].map(s => (
            <button key={s} style={filterBtn(slaStatus === s)} onClick={() => setSlaStatus(s)}>
              {s === '' ? 'All' : s === 'violated' ? 'Violated' : 'On Track'}
            </button>
          ))}
          <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, marginLeft: 12 }}>Fix:</span>
          {['', 'true', 'false'].map(s => (
            <button key={s} style={filterBtn(fixedFilter === s)} onClick={() => setFixedFilter(s)}>
              {s === '' ? 'All' : s === 'true' ? 'Fix Available' : 'No Fix'}
            </button>
          ))}
          <input
            style={{ ...inputStyle, marginLeft: 'auto', width: 220 }}
            placeholder="Search CVE, package, scan..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Findings Table */}
      <div style={card}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>
          Unique Vulnerabilities ({filteredFindings.length})
          {data.sla_violations > 0 && (
            <span style={{ color: 'var(--error)', fontSize: 13, fontWeight: 400, marginLeft: 8 }}>
              {data.sla_violations} SLA violation{data.sla_violations !== 1 ? 's' : ''}
            </span>
          )}
        </h2>

        {filteredFindings.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 24 }}>No findings match the current filters.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '8px 6px', cursor: 'pointer' }} onClick={() => toggleSort('severity')}>
                    Severity {sortField === 'severity' ? (sortDir === 'desc' ? '\u25BC' : '\u25B2') : ''}
                  </th>
                  <th style={{ textAlign: 'left', padding: '8px 6px' }}>Vulnerability</th>
                  <th style={{ textAlign: 'left', padding: '8px 6px' }}>Package</th>
                  <th style={{ textAlign: 'left', padding: '8px 6px' }}>Target</th>
                  <th style={{ textAlign: 'left', padding: '8px 6px', cursor: 'pointer' }} onClick={() => toggleSort('discovered_at')}>
                    First Seen {sortField === 'discovered_at' ? (sortDir === 'desc' ? '\u25BC' : '\u25B2') : ''}
                  </th>
                  <th style={{ textAlign: 'left', padding: '8px 6px', cursor: 'pointer' }} onClick={() => toggleSort('risk_score')}>
                    Risk {sortField === 'risk_score' ? (sortDir === 'desc' ? '\u25BC' : '\u25B2') : ''}
                  </th>
                  <th style={{ textAlign: 'left', padding: '8px 6px' }}>Fix Available</th>
                  <th style={{ textAlign: 'left', padding: '8px 6px', cursor: 'pointer', minWidth: 160 }} onClick={() => toggleSort('hours_elapsed')}>
                    SLA Status {sortField === 'hours_elapsed' ? (sortDir === 'desc' ? '\u25BC' : '\u25B2') : ''}
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map(f => (
                  <tr key={f.finding_id} style={{
                    background: f.sla_violated ? 'rgba(239,68,68,0.06)' : 'transparent',
                    borderBottom: '1px solid var(--border)',
                  }}>
                    <td style={{ padding: '8px 6px' }}>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td style={{ padding: '8px 6px', fontFamily: 'monospace' }}>
                      {f.vulnerability_id}
                    </td>
                    <td style={{ padding: '8px 6px' }}>
                      <span style={{ color: 'var(--text-primary)' }}>{f.package_name}</span>
                      <span style={{ color: 'var(--text-secondary)' }}>@{f.package_version}</span>
                    </td>
                    <td style={{ padding: '8px 6px' }}>
                      <Link to={`/scans/${f.scan_id}`} style={{ color: 'var(--accent)', fontSize: 12 }}>
                        {(f.target || f.scan_name).length > 35 ? (f.target || f.scan_name).slice(0, 35) + '...' : (f.target || f.scan_name)}
                      </Link>
                    </td>
                    <td style={{ padding: '8px 6px', color: 'var(--text-secondary)' }}>
                      {formatDateTime(f.discovered_at)}
                    </td>
                    <td style={{ padding: '8px 6px', fontWeight: 600 }}>
                      {f.risk_score.toFixed(1)}
                    </td>
                    <td style={{ padding: '8px 6px' }}>
                      {f.fix_version ? (
                        <span style={{ color: 'var(--warning)', display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
                          <Clock size={13} /> {f.fix_version}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>No fix</span>
                      )}
                    </td>
                    <td style={{ padding: '8px 6px' }}>
                      {f.sla_hours == null ? (
                        <span style={{ color: 'var(--text-secondary)', fontSize: 11, fontStyle: 'italic' }}>No SLA</span>
                      ) : (
                        <div>
                          {slaProgressBar(f)}
                          {f.sla_violated && (
                            <span style={{ color: 'var(--error)', fontSize: 10, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 3, marginTop: 2 }}>
                              <XCircle size={10} /> OVERDUE by {formatHours(f.hours_elapsed - f.sla_hours)}
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
