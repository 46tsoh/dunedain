import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronDown, ChevronRight, ExternalLink, BookOpen, ChevronUp } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import type { Finding, OsvVulnerability } from '../types';
import { getVulnDetail } from '../api/vulns';
import { formatDate } from '../utils';

interface Props { finding: Finding; }

// ---------------------------------------------------------------------------
// OSV detail sub-panel
// ---------------------------------------------------------------------------

function OsvDetailPanel({ vulnId }: { vulnId: string }) {
  const { data, isLoading, error } = useQuery<OsvVulnerability>({
    queryKey: ['vuln', vulnId],
    queryFn: () => getVulnDetail(vulnId),
    staleTime: 5 * 60 * 1000,
  });

  const panelStyle: React.CSSProperties = {
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    padding: 16,
    marginTop: 12,
  };

  const labelStyle: React.CSSProperties = {
    color: 'var(--text-secondary)',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    marginBottom: 4,
    display: 'block',
  };

  if (isLoading) {
    return (
      <div style={{ ...panelStyle, display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-secondary)', fontSize: 13 }}>
        <span className="spinner" style={{ width: 16, height: 16 }} /> Loading OSV details…
      </div>
    );
  }

  if (error || !data) {
    return (
      <div style={{ ...panelStyle, color: 'var(--error)', fontSize: 13 }}>
        Failed to load OSV details for {vulnId}.
      </div>
    );
  }

  const cweIds = (data.database_specific?.cwe_ids ?? []) as string[];

  return (
    <div style={panelStyle}>
      {/* Header row: dates + CWEs */}
      <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', marginBottom: 14 }}>
        {data.published && (
          <div>
            <span style={labelStyle}>Published</span>
            <span style={{ fontSize: 13 }}>{formatDate(data.published)}</span>
          </div>
        )}
        {data.modified && (
          <div>
            <span style={labelStyle}>Last Modified</span>
            <span style={{ fontSize: 13 }}>{formatDate(data.modified)}</span>
          </div>
        )}
        {cweIds.length > 0 && (
          <div>
            <span style={labelStyle}>CWE</span>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {cweIds.map(cwe => (
                <a
                  key={cwe}
                  href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                  target="_blank" rel="noreferrer"
                  style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--accent)' }}
                >
                  {cwe}
                </a>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Full description */}
      {data.details && (
        <div style={{ marginBottom: 14 }}>
          <span style={labelStyle}>Full Description</span>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.7, whiteSpace: 'pre-wrap', margin: 0 }}>
            {data.details}
          </p>
        </div>
      )}

      {/* CVSS vectors */}
      {data.severity && data.severity.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <span style={labelStyle}>CVSS Vectors</span>
          {data.severity.map((s, i) => (
            <div key={i} style={{
              fontFamily: 'monospace', fontSize: 11,
              color: 'var(--text-secondary)', marginBottom: 3,
              wordBreak: 'break-all',
            }}>
              <span style={{ color: 'var(--text-primary)', marginRight: 6 }}>{s.type}:</span>{s.score}
            </div>
          ))}
        </div>
      )}

      {/* Affected packages */}
      {data.affected && data.affected.filter(aff => aff.package).length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <span style={labelStyle}>Affected Packages</span>
          {data.affected.filter(aff => aff.package).map((aff, i) => (
            <div key={i} style={{
              background: 'var(--bg-secondary)', borderRadius: 4,
              padding: '8px 10px', marginBottom: 6,
              border: '1px solid var(--border)',
            }}>
              <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: 11 }}>{aff.package!.ecosystem} / </span>
                {aff.package!.name}
              </div>
              {aff.ranges?.map((range, j) => (
                <div key={j} style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  {range.events.map((evt, k) => (
                    <span key={k} style={{ display: 'inline-flex', gap: 4, marginRight: 12 }}>
                      {evt.introduced !== undefined && (
                        <span>introduced: <code style={{ color: 'var(--text-primary)' }}>{evt.introduced || '0'}</code></span>
                      )}
                      {evt.fixed !== undefined && (
                        <span>fixed: <code style={{ color: 'var(--success)' }}>{evt.fixed}</code></span>
                      )}
                      {evt.last_affected !== undefined && (
                        <span>last affected: <code style={{ color: 'var(--warning)' }}>{evt.last_affected}</code></span>
                      )}
                    </span>
                  ))}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* All references */}
      {data.references && data.references.length > 0 && (
        <div>
          <span style={labelStyle}>All References ({data.references.length})</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {data.references.map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  fontSize: 10, fontFamily: 'monospace',
                  color: 'var(--text-secondary)',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: 3, padding: '1px 4px',
                  minWidth: 64, textAlign: 'center',
                }}>
                  {r.type}
                </span>
                <a href={r.url} target="_blank" rel="noreferrer"
                  style={{ fontSize: 12, color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 480 }}>
                  {r.url}
                </a>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main FindingCard
// ---------------------------------------------------------------------------

export default function FindingCard({ finding }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [osvOpen, setOsvOpen] = useState(false);

  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 6,
      marginBottom: 8,
      background: 'var(--bg-card)',
    }}>
      {/* Summary row */}
      <button
        onClick={() => setExpanded(e => !e)}
        style={{
          width: '100%',
          display: 'grid',
          gridTemplateColumns: '1fr auto auto auto auto auto auto',
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
        <span style={{ fontFamily: 'monospace', fontSize: 13 }}>{finding.vulnerability_id}</span>
        <span style={{
          fontFamily: 'monospace', fontSize: 12,
          background: 'var(--bg-primary)',
          border: '1px solid var(--border)',
          borderRadius: 4,
          padding: '2px 7px',
          color: 'var(--text-primary)',
          whiteSpace: 'nowrap',
        }}>
          {finding.package_name}@{finding.package_version}
        </span>
        <SeverityBadge severity={finding.severity} />
        <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
          CVSS: {finding.cvss_score?.toFixed(1) ?? 'N/A'}
        </span>
        {finding.epss_score != null && (
          <span style={{
            fontSize: 11,
            fontFamily: 'monospace',
            padding: '2px 6px',
            borderRadius: 4,
            background: finding.epss_score >= 0.5
              ? 'rgba(239,68,68,0.15)'
              : finding.epss_score >= 0.1
                ? 'rgba(245,158,11,0.15)'
                : 'rgba(100,116,139,0.15)',
            color: finding.epss_score >= 0.5
              ? 'var(--critical)'
              : finding.epss_score >= 0.1
                ? 'var(--warning)'
                : 'var(--text-secondary)',
            whiteSpace: 'nowrap',
          }}>
            EPSS {(finding.epss_score * 100).toFixed(1)}%
          </span>
        )}
        <span style={{ color: finding.is_fixed ? 'var(--success)' : 'var(--text-secondary)', fontSize: 12 }}>
          {finding.is_fixed ? '✓ Fix available' : 'No fix'}
        </span>
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>

      {/* Expanded details */}
      {expanded && (
        <div style={{ padding: '0 14px 14px', borderTop: '1px solid var(--border)' }}>
          <p style={{ color: 'var(--text-secondary)', marginTop: 10, lineHeight: 1.6 }}>
            {finding.description || 'No description available.'}
          </p>

          {/* Metadata */}
          <div style={{ display: 'flex', gap: 24, marginTop: 12, flexWrap: 'wrap' }}>
            {finding.fix_version && (
              <div>
                <span style={{ color: 'var(--text-secondary)', fontSize: 11, textTransform: 'uppercase' }}>Fix Version</span>
                <div style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--success)' }}>{finding.fix_version}</div>
              </div>
            )}
            <div>
              <span style={{ color: 'var(--text-secondary)', fontSize: 11, textTransform: 'uppercase' }}>Risk Score</span>
              <div style={{ fontFamily: 'monospace', fontSize: 13 }}>{finding.risk_score?.toFixed(1) ?? 'N/A'}</div>
            </div>
            <div>
              <span style={{ color: 'var(--text-secondary)', fontSize: 11, textTransform: 'uppercase' }}>Ecosystem</span>
              <div style={{ fontSize: 13 }}>{finding.package_ecosystem}</div>
            </div>
            {finding.epss_score != null && (
              <div>
                <span style={{ color: 'var(--text-secondary)', fontSize: 11, textTransform: 'uppercase' }}>EPSS Score</span>
                <div style={{ fontFamily: 'monospace', fontSize: 13 }}>
                  {(finding.epss_score * 100).toFixed(2)}%
                  {finding.epss_percentile != null && (
                    <span style={{ color: 'var(--text-secondary)', fontSize: 11, marginLeft: 6 }}>
                      ({(finding.epss_percentile * 100).toFixed(0)}th percentile)
                    </span>
                  )}
                </div>
              </div>
            )}
            {finding.exploitable && (
              <div>
                <span style={{ fontSize: 11, color: 'var(--critical)' }}>u26a0 EXPLOITABLE</span>
              </div>
            )}
          </div>

          {/* Aliases */}
          {(finding.aliases ?? []).length > 0 && (
            <div style={{ marginTop: 10 }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: 11, textTransform: 'uppercase' }}>Aliases</span>
              <div style={{ marginTop: 4, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {(finding.aliases ?? []).map(a => (
                  <span key={a} style={{
                    background: 'var(--bg-primary)', border: '1px solid var(--border)',
                    borderRadius: 3, padding: '1px 6px', fontSize: 11, fontFamily: 'monospace',
                  }}>{a}</span>
                ))}
              </div>
            </div>
          )}

          {/* References (top 3 preview) */}
          {(finding.references ?? []).length > 0 && (
            <div style={{ marginTop: 10 }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: 11, textTransform: 'uppercase' }}>References</span>
              <div style={{ marginTop: 4, display: 'flex', flexDirection: 'column', gap: 3 }}>
                {(finding.references ?? []).slice(0, 3).map(r => (
                  <a key={r} href={r} target="_blank" rel="noreferrer"
                    style={{ fontSize: 12, color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <ExternalLink size={11} />{r}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Deep-dive OSV toggle */}
          <button
            onClick={() => setOsvOpen(o => !o)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              marginTop: 14, padding: '6px 12px',
              background: osvOpen ? 'rgba(59,130,246,0.15)' : 'transparent',
              border: '1px solid var(--accent)',
              borderRadius: 5, color: 'var(--accent)',
              cursor: 'pointer', fontSize: 12, fontWeight: 600,
            }}
          >
            <BookOpen size={13} />
            {osvOpen ? 'Hide' : 'View'} Full OSV Details
            {osvOpen ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>

          {osvOpen && <OsvDetailPanel vulnId={finding.vulnerability_id} />}
        </div>
      )}
    </div>
  );
}
