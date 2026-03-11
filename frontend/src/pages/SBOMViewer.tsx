import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Download } from 'lucide-react';
import { getSBOM } from '../api/sbom';
import { formatDateTime } from '../utils';

export default function SBOMViewer() {
  const { scanId } = useParams<{ scanId: string }>();
  const { data: sbom, isLoading, error } = useQuery({
    queryKey: ['sbom', scanId],
    queryFn: () => getSBOM(scanId!),
    enabled: !!scanId,
  });

  const handleDownload = () => {
    if (!sbom) return;
    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sbom-${scanId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><span className="spinner" style={{ width: 32, height: 32 }} /></div>;
  if (error || !sbom) return <div className="error-message">Failed to load SBOM or no SBOM available.</div>;

  const ecosystemCounts: Record<string, number> = {};
  sbom.components.forEach(c => {
    ecosystemCounts[c.ecosystem] = (ecosystemCounts[c.ecosystem] ?? 0) + 1;
  });

  return (
    <div>
      <Link to={`/scans/${scanId}`} style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)', fontSize: 13, marginBottom: 16 }}>
        <ArrowLeft size={14} /> Back to Scan
      </Link>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Software Bill of Materials</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
            Format: {sbom.format} · {sbom.components.length} components · Generated {formatDateTime(sbom.generated_at)}
          </p>
        </div>
        <button onClick={handleDownload} style={{
          display: 'flex', alignItems: 'center', gap: 6,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          color: 'var(--text-primary)', borderRadius: 6, padding: '8px 14px', cursor: 'pointer',
        }}>
          <Download size={14} /> Download JSON
        </button>
      </div>

      {/* Ecosystem summary */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 24 }}>
        {Object.entries(ecosystemCounts).map(([eco, count]) => (
          <div key={eco} style={{
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, padding: '8px 14px',
          }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{eco}</span>
            <span style={{ marginLeft: 8, fontWeight: 700 }}>{count}</span>
          </div>
        ))}
      </div>

      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        <table>
          <thead>
            <tr><th>Name</th><th>Version</th><th>Ecosystem</th><th>Licenses</th><th>PURL</th></tr>
          </thead>
          <tbody>
            {sbom.components.map((c, i) => (
              <tr key={i} style={{ background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                <td style={{ fontWeight: 500 }}>{c.name}</td>
                <td><code style={{ fontSize: 12, background: 'var(--bg-primary)', padding: '1px 5px', borderRadius: 3 }}>{c.version}</code></td>
                <td><span style={{ color: 'var(--accent)', fontSize: 12 }}>{c.ecosystem}</span></td>
                <td><span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{c.licenses.join(', ') || '—'}</span></td>
                <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-secondary)', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {c.purl ?? '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
