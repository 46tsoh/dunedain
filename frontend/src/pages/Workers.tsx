import { useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { getScans } from '../api/scans';
import { Link } from 'react-router-dom';
import type { Scan } from '../types';

const WORKER_COUNT = 3;
const CONCURRENCY = 8;

import { parseUTC } from '../utils';

/** Forces a re-render every `ms` milliseconds so elapsed clocks stay live. */
function useTick(ms = 1000) {
  const [, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), ms);
    return () => clearInterval(id);
  }, [ms]);
}

function elapsed(createdAt: string): string {
  const secs = Math.floor((Date.now() - parseUTC(createdAt).getTime()) / 1000);
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

function shortTarget(target: string, maxLen = 20): string {
  const parts = target.split('/');
  const tag = parts[parts.length - 1];
  return tag.length > maxLen ? tag.slice(0, maxLen - 1) + '…' : tag;
}

// ── Single LED slot ─────────────────────────────────────────────────────────
function Slot({ scan, index }: { scan: Scan | null; index: number }) {
  const active = scan !== null;
  const engine = scan?.scanner_engine;
  const ledColor = !active ? '#b45309' : engine === 'grype' ? '#a855f7' : '#22d3ee';
  const slotBg = active ? 'rgba(34,211,238,0.06)' : 'rgba(0,0,0,0.25)';
  const border = active ? `1px solid ${ledColor}44` : '1px solid #1e293b';

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 8,
      background: slotBg,
      border,
      borderRadius: 4,
      padding: '6px 10px',
      minWidth: 0,
      flex: 1,
      position: 'relative',
      overflow: 'hidden',
      transition: 'background 0.3s, border-color 0.3s',
    }}>
      {/* Scan-line shimmer on active slots */}
      {active && (
        <div style={{
          position: 'absolute',
          inset: 0,
          background: `linear-gradient(90deg, transparent 0%, ${ledColor}0a 50%, transparent 100%)`,
          animation: 'slotScan 2.4s linear infinite',
          pointerEvents: 'none',
        }} />
      )}

      {/* LED indicator */}
      <div style={{
        width: 8,
        height: 8,
        borderRadius: '50%',
        flexShrink: 0,
        background: ledColor,
        boxShadow: active ? `0 0 6px 2px ${ledColor}88` : 'none',
        animation: active ? 'ledBlink 1.8s ease-in-out infinite' : 'none',
      }} />

      {/* Content */}
      <div style={{ minWidth: 0, flex: 1 }}>
        {active && scan ? (
          <Link
            to={`/scans/${scan.id}`}
            title={scan.target}
            style={{
              color: '#e2e8f0',
              textDecoration: 'none',
              display: 'block',
            }}
          >
            {/* Ticker text */}
            <div style={{
              fontSize: 10,
              fontFamily: 'monospace',
              fontWeight: 700,
              color: ledColor,
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}>
              {shortTarget(scan.target)}
            </div>
            <div style={{
              fontSize: 9,
              color: '#64748b',
              marginTop: 1,
              fontFamily: 'monospace',
            }}>
              {elapsed(scan.created_at)}
            </div>
          </Link>
        ) : (
          <span style={{
            fontSize: 10,
            fontFamily: 'monospace',
            color: '#475569',
            letterSpacing: '0.05em',
          }}>
            STANDBY
          </span>
        )}
      </div>

      {/* Slot number badge */}
      <div style={{
        fontSize: 8,
        color: '#334155',
        fontFamily: 'monospace',
        flexShrink: 0,
        alignSelf: 'flex-start',
      }}>
        {String(index + 1).padStart(2, '0')}
      </div>
    </div>
  );
}

// ── 1U server unit ───────────────────────────────────────────────────────────
function ServerUnit({ workerIndex, slots }: { workerIndex: number; slots: (Scan | null)[] }) {
  const activeCount = slots.filter(Boolean).length;
  const load = activeCount / CONCURRENCY;
  const statusColor = load === 0 ? '#64748b' : load < 0.5 ? '#22c55e' : load < 0.9 ? '#eab308' : '#ef4444';

  return (
    <div style={{
      background: 'linear-gradient(180deg, #1a2235 0%, #111827 100%)',
      border: '1px solid #2d3f55',
      borderRadius: 6,
      overflow: 'hidden',
      boxShadow: '0 2px 12px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04)',
    }}>
      {/* Chassis top rail */}
      <div style={{
        height: 3,
        background: `linear-gradient(90deg, #0f172a, #1e3a5f ${load * 100}%, #0f172a ${load * 100}%)`,
        transition: 'background 0.5s',
      }} />

      {/* Face plate */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '10px 14px',
        borderBottom: '1px solid #1e293b',
        background: 'rgba(0,0,0,0.2)',
      }}>
        {/* Power button */}
        <div style={{
          width: 10,
          height: 10,
          borderRadius: '50%',
          border: `2px solid ${statusColor}`,
          boxShadow: `0 0 5px ${statusColor}`,
          flexShrink: 0,
          animation: activeCount > 0 ? 'powerPulse 2s ease-in-out infinite' : 'none',
        }} />

        {/* Unit label */}
        <div style={{
          fontSize: 11,
          fontWeight: 700,
          fontFamily: 'monospace',
          color: '#94a3b8',
          letterSpacing: '0.1em',
        }}>
          WORKER-{String(workerIndex + 1).padStart(2, '0')}
        </div>

        {/* Activity bar */}
        <div style={{
          flex: 1,
          height: 4,
          background: '#0f172a',
          borderRadius: 2,
          overflow: 'hidden',
          border: '1px solid #1e293b',
        }}>
          <div style={{
            height: '100%',
            width: `${load * 100}%`,
            background: `linear-gradient(90deg, ${statusColor}88, ${statusColor})`,
            borderRadius: 2,
            transition: 'width 0.4s ease',
          }} />
        </div>

        {/* Load label */}
        <div style={{
          fontSize: 10,
          fontFamily: 'monospace',
          color: statusColor,
          flexShrink: 0,
          minWidth: 42,
          textAlign: 'right',
        }}>
          {activeCount}/{CONCURRENCY}
        </div>

        {/* HDD activity light — flickers when busy */}
        <div style={{
          width: 6,
          height: 6,
          borderRadius: 1,
          background: activeCount > 0 ? '#3b82f6' : '#1e293b',
          boxShadow: activeCount > 0 ? '0 0 4px #3b82f6' : 'none',
          animation: activeCount > 0 ? 'hddFlicker 0.4s steps(1) infinite' : 'none',
          flexShrink: 0,
        }} />
      </div>

      {/* Slot bay — 2 rows of 4 */}
      <div style={{ padding: '10px 14px 12px', display: 'flex', flexDirection: 'column', gap: 5 }}>
        <div style={{ display: 'flex', gap: 5 }}>
          {slots.slice(0, 4).map((scan, i) => (
            <Slot key={i} scan={scan} index={i} />
          ))}
        </div>
        <div style={{ display: 'flex', gap: 5 }}>
          {slots.slice(4, 8).map((scan, i) => (
            <Slot key={i + 4} scan={scan} index={i + 4} />
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Rack enclosure ────────────────────────────────────────────────────────────
export default function Workers() {
  useTick(1000);

  const { data: allScans = [] } = useQuery<Scan[]>({
    queryKey: ['workers-scans'],
    queryFn: () => getScans(),
    refetchInterval: 1500,
  });

  const running = allScans.filter(s => s.status === 'running');
  const pending = allScans.filter(s => s.status === 'pending');
  const completed = allScans.filter(s => s.status === 'completed');
  const failed = allScans.filter(s => s.status === 'failed');

  // Distribute running scans across workers round-robin
  const workerSlots: (Scan | null)[][] = Array.from({ length: WORKER_COUNT }, () =>
    Array(CONCURRENCY).fill(null)
  );
  running.slice(0, WORKER_COUNT * CONCURRENCY).forEach((scan, i) => {
    const w = i % WORKER_COUNT;
    const s = Math.floor(i / WORKER_COUNT);
    workerSlots[w][s] = scan;
  });

  const totalActive = running.length;

  return (
    <div style={{ maxWidth: 960 }}>
      {/* Page header */}
      <div style={{ marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
          Worker Rack
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>
          {WORKER_COUNT} units · {CONCURRENCY} slots each · {WORKER_COUNT * CONCURRENCY} max parallel scans
        </p>
      </div>

      {/* Quick stats */}
      <div style={{
        display: 'flex',
        gap: 10,
        marginBottom: 24,
        flexWrap: 'wrap',
      }}>
        {[
          { label: 'ACTIVE',    value: totalActive,      color: '#22d3ee' },
          { label: 'QUEUED',    value: pending.length,   color: '#eab308' },
          { label: 'DONE',      value: completed.length, color: '#22c55e' },
          { label: 'FAILED',    value: failed.length,    color: '#ef4444' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{
            background: '#111827',
            border: `1px solid ${color}33`,
            borderRadius: 6,
            padding: '8px 16px',
            display: 'flex',
            alignItems: 'baseline',
            gap: 8,
            minWidth: 90,
          }}>
            <span style={{ fontSize: 20, fontWeight: 800, fontFamily: 'monospace', color }}>
              {value}
            </span>
            <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#475569', letterSpacing: '0.1em' }}>
              {label}
            </span>
          </div>
        ))}
      </div>

      {/* Rack enclosure */}
      <div style={{
        background: '#0d1117',
        border: '2px solid #2d3f55',
        borderRadius: 8,
        padding: '16px 14px',
        boxShadow: '0 8px 32px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.03)',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        marginBottom: 24,
        position: 'relative',
      }}>
        {/* Rack label strip */}
        <div style={{
          position: 'absolute',
          top: 6,
          right: 16,
          fontSize: 9,
          fontFamily: 'monospace',
          color: '#1e3a5f',
          letterSpacing: '0.15em',
          userSelect: 'none',
        }}>
          SCAN RACK · 3U
        </div>

        {/* Screw holes (decoration) */}
        {[0, 1, 2].map(i => (
          <div key={i} style={{
            position: 'absolute',
            left: 6,
            top: `${20 + i * 33.3}%`,
            width: 6,
            height: 6,
            borderRadius: '50%',
            background: '#0f172a',
            border: '1px solid #2d3f55',
          }} />
        ))}

        {workerSlots.map((slots, i) => (
          <ServerUnit key={i} workerIndex={i} slots={slots} />
        ))}
      </div>

      {/* Legend */}
      <div style={{
        display: 'flex',
        gap: 18,
        fontSize: 11,
        fontFamily: 'monospace',
        color: '#475569',
        marginBottom: 24,
        flexWrap: 'wrap',
        alignItems: 'center',
      }}>
        {[
          { dot: '#22d3ee', label: 'trivy' },
          { dot: '#a855f7', label: 'grype' },
          { dot: '#b45309', label: 'standby' },
        ].map(({ dot, label }) => (
          <span key={label} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{
              display: 'inline-block', width: 7, height: 7,
              borderRadius: '50%', background: dot,
              boxShadow: `0 0 4px ${dot}`,
            }} />
            {label.toUpperCase()}
          </span>
        ))}
        <span style={{ marginLeft: 'auto' }}>click any active slot to open scan</span>
      </div>

      {/* Pending queue */}
      {pending.length > 0 && (
        <div style={{
          background: '#0d1117',
          border: '1px solid #2d3f55',
          borderRadius: 6,
          overflow: 'hidden',
        }}>
          <div style={{
            padding: '10px 16px',
            borderBottom: '1px solid #1e293b',
            fontFamily: 'monospace',
            fontSize: 11,
            color: '#eab308',
            letterSpacing: '0.1em',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}>
            <span style={{
              display: 'inline-block', width: 7, height: 7,
              borderRadius: '50%', background: '#eab308',
              boxShadow: '0 0 5px #eab308',
              animation: 'ledBlink 1.2s ease-in-out infinite',
            }} />
            QUEUE · {pending.length} JOB{pending.length !== 1 ? 'S' : ''} WAITING
          </div>
          <table style={{ fontFamily: 'monospace', fontSize: 11 }}>
            <thead>
              <tr>
                <th style={{ color: '#334155' }}>TARGET</th>
                <th style={{ color: '#334155' }}>TYPE</th>
                <th style={{ color: '#334155' }}>WAITING</th>
              </tr>
            </thead>
            <tbody>
              {pending.map(scan => (
                <tr key={scan.id} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td>
                    <Link to={`/scans/${scan.id}`} style={{ color: '#94a3b8' }}>
                      {scan.target}
                    </Link>
                  </td>
                  <td style={{ color: '#475569' }}>{scan.scan_type}</td>
                  <td style={{ color: '#475569' }}>{elapsed(scan.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Animations */}
      <style>{`
        @keyframes ledBlink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.3; }
        }
        @keyframes powerPulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        @keyframes hddFlicker {
          0%   { opacity: 1; }
          25%  { opacity: 0.1; }
          50%  { opacity: 0.9; }
          75%  { opacity: 0.2; }
          100% { opacity: 1; }
        }
        @keyframes slotScan {
          0%   { transform: translateX(-100%); }
          100% { transform: translateX(200%); }
        }
      `}</style>
    </div>
  );
}
