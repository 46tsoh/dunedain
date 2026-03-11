import { useQuery } from '@tanstack/react-query';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { AlertTriangle, Activity, ScanLine, Shield } from 'lucide-react';
import { getDashboard } from '../api/reports';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';
import { Link } from 'react-router-dom';
import { formatDate } from '../utils';

const card = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  padding: '20px 24px',
};

export default function Dashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard'],
    queryFn: getDashboard,
  });

  if (isLoading) return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}>
      <span className="spinner" style={{ width: 32, height: 32 }} />
    </div>
  );

  if (error || !data) return (
    <div className="error-message">Failed to load dashboard data. Is the backend running?</div>
  );

  const chartData = [
    { name: 'Critical',   value: data.critical_count,   color: '#ef4444' },
    { name: 'High',       value: data.high_count,        color: '#f97316' },
    { name: 'Medium',     value: data.medium_count,      color: '#eab308' },
    { name: 'Low',        value: data.low_count,         color: '#22c55e' },
    { name: 'Negligible', value: data.negligible_count ?? 0, color: '#6366f1' },
    { name: 'Unknown',    value: data.unknown_count ?? 0,    color: '#94a3b8' },
  ];

  const statCards = [
    { label: 'Total Scans',    value: data.total_scans,    icon: ScanLine,     color: 'var(--accent)' },
    { label: 'Total Findings', value: data.total_findings, icon: Activity,     color: 'var(--text-secondary)' },
    { label: 'Critical',       value: data.critical_count, icon: AlertTriangle, color: 'var(--critical)' },
    { label: 'High',           value: data.high_count,     icon: Shield,       color: 'var(--high)' },
  ];

  return (
    <div>
      <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 24 }}>Dashboard</h1>

      {/* Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {statCards.map(({ label, value, icon: Icon, color }) => (
          <div key={label} style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ color: 'var(--text-secondary)', fontSize: 12, marginBottom: 6 }}>{label}</div>
                <div style={{ fontSize: 32, fontWeight: 700, color }}>{value}</div>
              </div>
              <Icon size={20} color={color} />
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
        {/* Bar Chart */}
        <div style={card}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={220}>
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
                {chartData.map((entry) => (
                  <Cell key={entry.name} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Top Vulnerabilities */}
        <div style={card}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Top Vulnerabilities</h2>
          {data.top_vulnerabilities.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)' }}>No vulnerabilities found.</p>
          ) : (
            <div>
              {data.top_vulnerabilities.slice(0, 8).map(v => (
                <div key={v.vulnerability_id} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '8px 0', borderBottom: '1px solid var(--border)',
                }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{v.vulnerability_id}</span>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <SeverityBadge severity={v.severity} />
                    <span style={{
                      background: 'var(--bg-primary)',
                      border: '1px solid var(--border)',
                      borderRadius: 10,
                      padding: '1px 8px',
                      fontSize: 11,
                      color: 'var(--text-secondary)',
                    }}>{v.count}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div style={card}>
        <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 16 }}>Recent Scans</h2>
        {data.recent_scans.length === 0 ? (
          <p style={{ color: 'var(--text-secondary)' }}>No scans yet. <Link to="/scans">Start a scan</Link></p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Critical</th>
                <th>Date</th>
              </tr>
            </thead>
            <tbody>
              {data.recent_scans.map(scan => (
                <tr key={scan.id} style={{ cursor: 'pointer' }}>
                  <td>
                    <Link to={`/scans/${scan.id}`} style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                      {scan.name}
                    </Link>
                  </td>
                  <td><span style={{ color: 'var(--text-secondary)' }}>{scan.scan_type}</span></td>
                  <td><StatusBadge status={scan.status} /></td>
                  <td>{scan.findings_count}</td>
                  <td><span style={{ color: scan.critical_count > 0 ? 'var(--critical)' : 'var(--text-secondary)' }}>{scan.critical_count}</span></td>
                  <td><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{formatDate(scan.created_at)}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
