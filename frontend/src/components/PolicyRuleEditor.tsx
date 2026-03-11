import { Trash2, Plus } from 'lucide-react';
import type { PolicyRule } from '../types';

interface Props {
  rules: PolicyRule[];
  onChange: (rules: PolicyRule[]) => void;
}

export default function PolicyRuleEditor({ rules, onChange }: Props) {
  const addRule = () => {
    onChange([...rules, { type: 'severity_threshold', min_severity: 'HIGH' }]);
  };

  const updateRule = (index: number, updated: Partial<PolicyRule>) => {
    onChange(rules.map((r, i) => i === index ? { ...r, ...updated } : r));
  };

  const removeRule = (index: number) => {
    onChange(rules.filter((_, i) => i !== index));
  };

  const inputStyle = {
    background: 'var(--bg-primary)',
    border: '1px solid var(--border)',
    borderRadius: 4,
    color: 'var(--text-primary)',
    padding: '6px 10px',
    width: '100%',
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ color: 'var(--text-secondary)', fontSize: 12, textTransform: 'uppercase', fontWeight: 600 }}>
          Rules
        </span>
        <button type="button" onClick={addRule} style={{
          display: 'flex', alignItems: 'center', gap: 4,
          background: 'var(--accent)', color: '#fff', border: 'none',
          borderRadius: 4, padding: '4px 10px', fontSize: 12,
        }}>
          <Plus size={12} /> Add Rule
        </button>
      </div>
      {rules.map((rule, i) => (
        <div key={i} style={{
          border: '1px solid var(--border)',
          borderRadius: 6,
          padding: 12,
          marginBottom: 8,
          background: 'var(--bg-primary)',
          display: 'flex',
          flexDirection: 'column',
          gap: 8,
        }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <select value={rule.type} onChange={e => updateRule(i, { type: e.target.value as PolicyRule['type'] })}
              style={{ ...inputStyle, flex: 1 }}>
              <option value="severity_threshold">Severity Threshold</option>
              <option value="cvss_threshold">CVSS Threshold</option>
              <option value="fix_available">Fix Available</option>
              <option value="package_blocklist">Package Blocklist</option>
            </select>
            <button onClick={() => removeRule(i)} style={{
              background: 'transparent', border: 'none', color: 'var(--error)', padding: 4,
            }}>
              <Trash2 size={14} />
            </button>
          </div>
          {rule.type === 'severity_threshold' && (
            <select value={rule.min_severity ?? 'HIGH'}
              onChange={e => updateRule(i, { min_severity: e.target.value })}
              style={inputStyle}>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="NEGLIGIBLE">NEGLIGIBLE</option>
              <option value="UNKNOWN">UNKNOWN</option>
            </select>
          )}
          {rule.type === 'cvss_threshold' && (
            <input type="number" min={0} max={10} step={0.1}
              value={rule.min_score ?? 7.0}
              onChange={e => updateRule(i, { min_score: parseFloat(e.target.value) })}
              style={inputStyle}
              placeholder="Min CVSS score (0-10)"
            />
          )}
          {rule.type === 'fix_available' && (
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-secondary)' }}>
              <input type="checkbox"
                checked={rule.require_fix ?? true}
                onChange={e => updateRule(i, { require_fix: e.target.checked })}
              />
              Require fix to be available
            </label>
          )}
          {rule.type === 'package_blocklist' && (
            <textarea
              value={(rule.packages ?? []).join('\n')}
              onChange={e => updateRule(i, { packages: e.target.value.split('\n').filter(Boolean) })}
              style={{ ...inputStyle, height: 80, resize: 'vertical' }}
              placeholder="One package name per line"
            />
          )}
        </div>
      ))}
      {rules.length === 0 && (
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, fontStyle: 'italic' }}>
          No rules configured. Click "Add Rule" to add one.
        </p>
      )}
    </div>
  );
}
