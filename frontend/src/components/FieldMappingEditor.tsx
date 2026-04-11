import { Plus, RotateCcw, Trash2 } from 'lucide-react';

interface FieldMappingEditorProps {
  mappings: Array<{
    source: string;
    target_field: string;
    transform: string | null;
    template_value: string | null;
    priority: number;
  }>;
  onChange: (mappings: FieldMappingEditorProps['mappings']) => void;
}

const inputStyle: React.CSSProperties = {
  background: 'var(--bg-primary)',
  border: '1px solid var(--border)',
  borderRadius: 4,
  color: 'var(--text-primary)',
  padding: '6px 10px',
  width: '100%',
};

const sourceOptions = [
  'finding.vulnerability_id',
  'finding.severity',
  'finding.package_name',
  'finding.package_version',
  'finding.package_ecosystem',
  'finding.description',
  'finding.cvss_score',
  'finding.fix_version',
  'finding.risk_score',
  'scan.target',
  'scan.scan_type',
  '_static',
] as const;

const defaultMappings: FieldMappingEditorProps['mappings'] = [
  {
    source: '_static',
    target_field: 'summary',
    transform: 'template',
    template_value: '[{{finding.severity}}] {{finding.vulnerability_id}} in {{finding.package_name}}@{{finding.package_version}}',
    priority: 100,
  },
  {
    source: 'finding.description',
    target_field: 'description',
    transform: null,
    template_value: null,
    priority: 90,
  },
  {
    source: 'finding.severity',
    target_field: 'priority',
    transform: 'severity_to_priority',
    template_value: null,
    priority: 80,
  },
  {
    source: '_static',
    target_field: 'labels',
    transform: 'static_value',
    template_value: 'security-vulnerability',
    priority: 70,
  },
];

export default function FieldMappingEditor({ mappings, onChange }: FieldMappingEditorProps) {
  const addMapping = () => {
    onChange([
      ...mappings,
      {
        source: 'finding.vulnerability_id',
        target_field: '',
        transform: null,
        template_value: null,
        priority: mappings.length + 1,
      },
    ]);
  };

  const updateMapping = (index: number, updated: Partial<FieldMappingEditorProps['mappings'][number]>) => {
    onChange(mappings.map((mapping, i) => (i === index ? { ...mapping, ...updated } : mapping)));
  };

  const removeMapping = (index: number) => {
    onChange(mappings.filter((_, i) => i !== index));
  };

  const loadDefaults = () => {
    onChange(defaultMappings);
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <span style={{ color: 'var(--text-secondary)', fontSize: 12, textTransform: 'uppercase', fontWeight: 600 }}>
          Field Mappings
        </span>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            onClick={loadDefaults}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              background: 'transparent',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '4px 10px',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            <RotateCcw size={12} /> Load Defaults
          </button>
          <button
            type="button"
            onClick={addMapping}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              background: 'var(--accent)',
              color: '#fff',
              border: 'none',
              borderRadius: 4,
              padding: '4px 10px',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            <Plus size={12} /> Add Mapping
          </button>
        </div>
      </div>

      {mappings.length === 0 && (
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, fontStyle: 'italic', margin: '6px 0 0' }}>
          No mappings configured. Add a mapping or load defaults.
        </p>
      )}

      {mappings.map((mapping, index) => {
        const showTemplateInput = mapping.transform === 'template' || mapping.transform === 'static_value';

        return (
          <div
            key={`${mapping.source}-${mapping.target_field}-${index}`}
            style={{
              border: '1px solid var(--border)',
              borderRadius: 6,
              padding: 12,
              marginBottom: 10,
              background: 'var(--bg-primary)',
            }}
          >
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1fr 84px 36px', gap: 8, alignItems: 'end' }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Source</label>
                <select
                  value={mapping.source}
                  onChange={event => updateMapping(index, { source: event.target.value })}
                  style={{ ...inputStyle, marginTop: 4 }}
                >
                  {sourceOptions.map(option => (
                    <option key={option} value={option}>{option}</option>
                  ))}
                </select>
              </div>

              <div>
                <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Target Field</label>
                <input
                  value={mapping.target_field}
                  onChange={event => updateMapping(index, { target_field: event.target.value })}
                  placeholder="summary"
                  style={{ ...inputStyle, marginTop: 4 }}
                />
              </div>

              <div>
                <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Transform</label>
                <select
                  value={mapping.transform ?? ''}
                  onChange={event => updateMapping(index, { transform: event.target.value || null })}
                  style={{ ...inputStyle, marginTop: 4 }}
                >
                  <option value="">(none)</option>
                  <option value="template">template</option>
                  <option value="severity_to_priority">severity_to_priority</option>
                  <option value="static_value">static_value</option>
                  <option value="append_label">append_label</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Priority</label>
                <input
                  type="number"
                  value={mapping.priority}
                  onChange={event => updateMapping(index, { priority: Number(event.target.value) || 0 })}
                  style={{ ...inputStyle, marginTop: 4 }}
                />
              </div>

              <button
                type="button"
                onClick={() => removeMapping(index)}
                style={{
                  background: 'transparent',
                  border: '1px solid var(--border)',
                  borderRadius: 4,
                  color: 'var(--error)',
                  cursor: 'pointer',
                  height: 33,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
                title="Remove mapping"
              >
                <Trash2 size={14} />
              </button>
            </div>

            {showTemplateInput && (
              <div style={{ marginTop: 8 }}>
                <label style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Template / Static Value</label>
                <input
                  value={mapping.template_value ?? ''}
                  onChange={event => updateMapping(index, { template_value: event.target.value || null })}
                  placeholder={mapping.transform === 'template' ? '{{finding.vulnerability_id}}' : 'security-vulnerability'}
                  style={{ ...inputStyle, marginTop: 4 }}
                />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
