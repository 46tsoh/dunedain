const config: Record<string, { bg: string; color: string; label: string }> = {
  pending:     { bg: 'rgba(148,163,184,0.15)', color: 'var(--text-secondary)', label: 'Pending' },
  running:     { bg: 'rgba(59,130,246,0.15)',  color: 'var(--accent)',         label: 'Running' },
  completed:   { bg: 'rgba(34,197,94,0.15)',   color: 'var(--success)',        label: 'Completed' },
  failed:      { bg: 'rgba(239,68,68,0.15)',   color: 'var(--error)',          label: 'Failed' },
  unsupported: { bg: 'rgba(234,179,8,0.15)',   color: '#ca8a04',               label: 'Unsupported' },
};

interface Props { status: string; }

export default function StatusBadge({ status }: Props) {
  const { bg, color, label } = config[status] ?? config.pending;
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: 11,
      fontWeight: 600,
      background: bg,
      color,
    }}>
      {label}
    </span>
  );
}
