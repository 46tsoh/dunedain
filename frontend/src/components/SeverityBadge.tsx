const colors: Record<string, { bg: string; color: string }> = {
  CRITICAL:   { bg: 'rgba(239,68,68,0.15)',   color: 'var(--critical)' },
  HIGH:       { bg: 'rgba(249,115,22,0.15)',   color: 'var(--high)' },
  MEDIUM:     { bg: 'rgba(234,179,8,0.15)',    color: 'var(--medium)' },
  LOW:        { bg: 'rgba(34,197,94,0.15)',    color: 'var(--low)' },
  NEGLIGIBLE: { bg: 'rgba(99,102,241,0.15)',   color: 'var(--negligible)' },
  UNKNOWN:    { bg: 'rgba(148,163,184,0.15)',  color: 'var(--text-secondary)' },
};

interface Props { severity: string; }

export default function SeverityBadge({ severity }: Props) {
  const { bg, color } = colors[severity] ?? colors.UNKNOWN;
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: '0.05em',
      background: bg,
      color,
    }}>
      {severity}
    </span>
  );
}
