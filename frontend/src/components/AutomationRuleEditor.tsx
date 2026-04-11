import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Plus, Trash2, X } from 'lucide-react';
import { getIntegrations } from '../api/integrations';
import { getTeams } from '../api/teams';

interface AutomationRuleEditorProps {
  title: string;
  submitLabel: string;
  initialRule?: {
    name: string;
    description: string;
    trigger: string;
    conditions: Array<Record<string, unknown>>;
    actions: Array<Record<string, unknown>>;
    integration_id: string;
    team_id: string;
  };
  triggers: string[];
  submitting: boolean;
  error: string;
  onClose: () => void;
  onSubmit: (data: {
    name: string;
    description: string | null;
    trigger: string;
    conditions: Array<Record<string, unknown>>;
    actions: Array<Record<string, unknown>>;
    integration_id: string | null;
    team_id: string | null;
  }) => void;
}

type EditorForm = {
  name: string;
  description: string;
  trigger: string;
  conditions: Array<Record<string, unknown>>;
  actions: Array<Record<string, unknown>>;
  integration_id: string;
  team_id: string;
};

const CONDITION_TYPES = [
  'severity_gte',
  'cvss_gte',
  'status_equals',
  'priority_equals',
  'package_matches',
  'ecosystem_equals',
  'team_equals',
  'has_fix',
  'ticket_status_in',
] as const;

const ACTION_TYPES = [
  'create_ticket',
  'add_comment',
  'transition_ticket',
  'accept_risk',
  'send_notification',
  'update_priority',
  'rerun_scan',
] as const;

const overlayStyle: React.CSSProperties = {
  position: 'fixed',
  inset: 0,
  background: 'rgba(0,0,0,0.6)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  zIndex: 100,
};

const modalStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 10,
  padding: 24,
  width: 720,
  maxWidth: '96vw',
  maxHeight: '92vh',
  overflowY: 'auto',
};

const inputStyle: React.CSSProperties = {
  background: 'var(--bg-primary)',
  border: '1px solid var(--border)',
  borderRadius: 4,
  color: 'var(--text-primary)',
  padding: '8px 12px',
  width: '100%',
  marginTop: 4,
  boxSizing: 'border-box',
};

const buttonPrimary: React.CSSProperties = {
  background: 'var(--accent)',
  color: 'var(--text-primary)',
  border: 'none',
  borderRadius: 6,
  padding: '8px 16px',
  fontWeight: 600,
  cursor: 'pointer',
};

const buttonSecondary: React.CSSProperties = {
  background: 'transparent',
  border: '1px solid var(--border)',
  color: 'var(--text-secondary)',
  borderRadius: 6,
  padding: '8px 16px',
  cursor: 'pointer',
};

function readString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function readNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  return fallback;
}

function conditionDefault(type: (typeof CONDITION_TYPES)[number]): Record<string, unknown> {
  if (type === 'severity_gte') {
    return { type, severity: 'HIGH' };
  }
  if (type === 'cvss_gte') {
    return { type, score: 7.0 };
  }
  if (type === 'status_equals') {
    return { type, status: '' };
  }
  if (type === 'priority_equals') {
    return { type, priority: '' };
  }
  if (type === 'package_matches') {
    return { type, pattern: '' };
  }
  if (type === 'ecosystem_equals') {
    return { type, ecosystem: '' };
  }
  if (type === 'team_equals') {
    return { type, team_id: '' };
  }
  if (type === 'has_fix') {
    return { type, value: true };
  }
  if (type === 'ticket_status_in') {
    return { type, values: ['Done', 'Closed'] };
  }
  return { type };
}

function actionDefault(type: (typeof ACTION_TYPES)[number]): Record<string, unknown> {
  if (type === 'create_ticket') {
    return { type, integration_id: '' };
  }
  if (type === 'add_comment') {
    return { type, body: '' };
  }
  if (type === 'transition_ticket') {
    return { type, target_status: '' };
  }
  if (type === 'send_notification') {
    return { type, channel: '', message: '' };
  }
  if (type === 'update_priority') {
    return { type, priority: '' };
  }
  return { type };
}

function emptyRule(triggers: string[]): EditorForm {
  return {
    name: '',
    description: '',
    trigger: triggers[0] ?? 'scan_completed',
    conditions: [],
    actions: [],
    integration_id: '',
    team_id: '',
  };
}

export default function AutomationRuleEditor({
  title,
  submitLabel,
  initialRule,
  triggers,
  submitting,
  error,
  onClose,
  onSubmit,
}: AutomationRuleEditorProps) {
  const [form, setForm] = useState<EditorForm>(() => initialRule ?? emptyRule(triggers));

  const { data: integrations } = useQuery({
    queryKey: ['integrations'],
    queryFn: getIntegrations,
  });

  const { data: teams } = useQuery({
    queryKey: ['teams'],
    queryFn: getTeams,
  });

  const canSubmit = useMemo(() => {
    if (!form.name.trim()) return false;
    if (!form.trigger.trim()) return false;
    return true;
  }, [form.name, form.trigger]);

  const addCondition = () => {
    setForm(current => ({
      ...current,
      conditions: [...current.conditions, conditionDefault('severity_gte')],
    }));
  };

  const updateCondition = (index: number, patch: Record<string, unknown>) => {
    setForm(current => ({
      ...current,
      conditions: current.conditions.map((condition, i) => (i === index ? { ...condition, ...patch } : condition)),
    }));
  };

  const removeCondition = (index: number) => {
    setForm(current => ({
      ...current,
      conditions: current.conditions.filter((_, i) => i !== index),
    }));
  };

  const addAction = () => {
    setForm(current => ({
      ...current,
      actions: [...current.actions, actionDefault('add_comment')],
    }));
  };

  const updateAction = (index: number, patch: Record<string, unknown>) => {
    setForm(current => ({
      ...current,
      actions: current.actions.map((action, i) => (i === index ? { ...action, ...patch } : action)),
    }));
  };

  const removeAction = (index: number) => {
    setForm(current => ({
      ...current,
      actions: current.actions.filter((_, i) => i !== index),
    }));
  };

  return (
    <div style={overlayStyle} onClick={onClose}>
      <div style={modalStyle} onClick={event => event.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>{title}</h2>
          <button
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
          >
            <X size={20} />
          </button>
        </div>

        {error && (
          <div
            style={{
              marginBottom: 14,
              border: '1px solid var(--error)',
              background: 'var(--bg-primary)',
              color: 'var(--error)',
              borderRadius: 6,
              padding: '8px 10px',
              fontSize: 13,
            }}
          >
            {error}
          </div>
        )}

        <form
          onSubmit={event => {
            event.preventDefault();
            onSubmit({
              name: form.name.trim(),
              description: form.description.trim() || null,
              trigger: form.trigger,
              conditions: form.conditions,
              actions: form.actions,
              integration_id: form.integration_id.trim() || null,
              team_id: form.team_id.trim() || null,
            });
          }}
        >
          <div style={{ marginBottom: 14 }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Name *</label>
            <input
              required
              value={form.name}
              onChange={event => setForm(current => ({ ...current, name: event.target.value }))}
              style={inputStyle}
              placeholder="Rule name"
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Description</label>
            <textarea
              value={form.description}
              onChange={event => setForm(current => ({ ...current, description: event.target.value }))}
              style={{ ...inputStyle, minHeight: 70, resize: 'vertical' }}
              placeholder="What this rule does"
            />
          </div>

          <div style={{ marginBottom: 18 }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Trigger *</label>
            <select
              required
              value={form.trigger}
              onChange={event => setForm(current => ({ ...current, trigger: event.target.value }))}
              style={inputStyle}
            >
              {triggers.map(trigger => (
                <option key={trigger} value={trigger}>
                  {trigger}
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginBottom: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: 12, textTransform: 'uppercase', fontWeight: 600 }}>
                Conditions
              </span>
              <button
                type="button"
                onClick={addCondition}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                  background: 'var(--accent)',
                  color: 'var(--text-primary)',
                  border: 'none',
                  borderRadius: 4,
                  padding: '4px 10px',
                  fontSize: 12,
                  cursor: 'pointer',
                }}
              >
                <Plus size={12} /> Add Condition
              </button>
            </div>

            {form.conditions.map((condition, index) => {
              const type = readString(condition.type, 'severity_gte') as (typeof CONDITION_TYPES)[number];

              return (
                <div
                  key={`${type}-${index}`}
                  style={{
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    padding: 12,
                    marginBottom: 8,
                    background: 'var(--bg-primary)',
                  }}
                >
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <select
                      value={type}
                      onChange={event => {
                        const nextType = event.target.value as (typeof CONDITION_TYPES)[number];
                        updateCondition(index, conditionDefault(nextType));
                      }}
                      style={{ ...inputStyle, marginTop: 0, flex: 1 }}
                    >
                      {CONDITION_TYPES.map(ct => (
                        <option key={ct} value={ct}>{ct}</option>
                      ))}
                    </select>
                    <button
                      type="button"
                      onClick={() => removeCondition(index)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--error)',
                        padding: 4,
                        cursor: 'pointer',
                      }}
                    >
                      <X size={14} />
                    </button>
                  </div>

                  {type === 'severity_gte' && (
                    <select
                      value={readString(condition.severity, 'HIGH')}
                      onChange={event => updateCondition(index, { severity: event.target.value })}
                      style={inputStyle}
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  )}

                  {type === 'cvss_gte' && (
                    <input
                      type="number"
                      min={0}
                      max={10}
                      step={0.1}
                      value={readNumber(condition.score, 7.0)}
                      onChange={event => updateCondition(index, { score: Number(event.target.value) })}
                      style={inputStyle}
                      placeholder="Score 0-10"
                    />
                  )}

                  {type === 'status_equals' && (
                    <input
                      value={readString(condition.status)}
                      onChange={event => updateCondition(index, { status: event.target.value })}
                      style={inputStyle}
                      placeholder="Status"
                    />
                  )}

                  {type === 'priority_equals' && (
                    <input
                      value={readString(condition.priority)}
                      onChange={event => updateCondition(index, { priority: event.target.value })}
                      style={inputStyle}
                      placeholder="Priority"
                    />
                  )}

                  {type === 'package_matches' && (
                    <input
                      value={readString(condition.pattern)}
                      onChange={event => updateCondition(index, { pattern: event.target.value })}
                      style={inputStyle}
                      placeholder="Pattern (glob)"
                    />
                  )}

                  {type === 'ecosystem_equals' && (
                    <input
                      value={readString(condition.ecosystem)}
                      onChange={event => updateCondition(index, { ecosystem: event.target.value })}
                      style={inputStyle}
                      placeholder="Ecosystem"
                    />
                  )}

                  {type === 'team_equals' && (
                    <select
                      value={readString(condition.team_id)}
                      onChange={event => updateCondition(index, { team_id: event.target.value })}
                      style={inputStyle}
                    >
                      <option value="">Select a team</option>
                      {teams?.map(t => (
                        <option key={t.id} value={t.id}>{t.name}</option>
                      ))}
                    </select>
                  )}

                  {type === 'has_fix' && (
                    <select
                      value={condition.value === false ? 'false' : 'true'}
                      onChange={event => updateCondition(index, { value: event.target.value === 'true' })}
                      style={inputStyle}
                    >
                      <option value="true">Has fix available</option>
                      <option value="false">No fix available</option>
                    </select>
                  )}

                  {type === 'ticket_status_in' && (
                    <input
                      value={Array.isArray(condition.values) ? (condition.values as string[]).join(', ') : ''}
                      onChange={event =>
                        updateCondition(index, {
                          values: event.target.value.split(',').map((s: string) => s.trim()).filter(Boolean),
                        })
                      }
                      style={inputStyle}
                      placeholder="Comma-separated statuses (e.g. Done, Closed)"
                    />
                  )}
                </div>
              );
            })}

            {form.conditions.length === 0 && (
              <p style={{ color: 'var(--text-secondary)', fontSize: 13, fontStyle: 'italic' }}>
                No conditions configured.
              </p>
            )}
          </div>

          <div style={{ marginBottom: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: 12, textTransform: 'uppercase', fontWeight: 600 }}>
                Actions
              </span>
              <button
                type="button"
                onClick={addAction}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 4,
                  background: 'var(--accent)',
                  color: 'var(--text-primary)',
                  border: 'none',
                  borderRadius: 4,
                  padding: '4px 10px',
                  fontSize: 12,
                  cursor: 'pointer',
                }}
              >
                <Plus size={12} /> Add Action
              </button>
            </div>

            {form.actions.map((action, index) => {
              const type = readString(action.type, 'add_comment') as (typeof ACTION_TYPES)[number];

              return (
                <div
                  key={`${type}-${index}`}
                  style={{
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    padding: 12,
                    marginBottom: 8,
                    background: 'var(--bg-primary)',
                  }}
                >
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <select
                      value={type}
                      onChange={event => {
                        const nextType = event.target.value as (typeof ACTION_TYPES)[number];
                        updateAction(index, actionDefault(nextType));
                      }}
                      style={{ ...inputStyle, marginTop: 0, flex: 1 }}
                    >
                      {ACTION_TYPES.map(at => (
                        <option key={at} value={at}>{at}</option>
                      ))}
                    </select>
                    <button
                      type="button"
                      onClick={() => removeAction(index)}
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--error)',
                        padding: 4,
                        cursor: 'pointer',
                      }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>

                  {type === 'create_ticket' && (
                    <select
                      value={readString(action.integration_id)}
                      onChange={event => updateAction(index, { integration_id: event.target.value })}
                      style={inputStyle}
                    >
                      <option value="">Select an integration (optional)</option>
                      {integrations?.map(i => (
                        <option key={i.id} value={i.id}>{i.name} ({i.provider})</option>
                      ))}
                    </select>
                  )}

                  {type === 'add_comment' && (
                    <textarea
                      value={readString(action.body)}
                      onChange={event => updateAction(index, { body: event.target.value })}
                      style={{ ...inputStyle, minHeight: 70, resize: 'vertical' }}
                      placeholder="Comment body template"
                    />
                  )}

                  {type === 'transition_ticket' && (
                    <input
                      value={readString(action.target_status)}
                      onChange={event => updateAction(index, { target_status: event.target.value })}
                      style={inputStyle}
                      placeholder="Target status"
                    />
                  )}

                  {type === 'send_notification' && (
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                      <input
                        value={readString(action.channel)}
                        onChange={event => updateAction(index, { channel: event.target.value })}
                        style={inputStyle}
                        placeholder="Channel"
                      />
                      <input
                        value={readString(action.message)}
                        onChange={event => updateAction(index, { message: event.target.value })}
                        style={inputStyle}
                        placeholder="Message"
                      />
                    </div>
                  )}

                  {type === 'update_priority' && (
                    <input
                      value={readString(action.priority)}
                      onChange={event => updateAction(index, { priority: event.target.value })}
                      style={inputStyle}
                      placeholder="Priority"
                    />
                  )}

                  {type === 'rerun_scan' && (
                    <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginTop: 6, fontStyle: 'italic' }}>
                      Re-runs the scan associated with this event. No additional configuration needed.
                    </p>
                  )}
                </div>
              );
            })}

            {form.actions.length === 0 && (
              <p style={{ color: 'var(--text-secondary)', fontSize: 13, fontStyle: 'italic' }}>
                No actions configured.
              </p>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Integration</label>
              <select
                value={form.integration_id}
                onChange={event => setForm(current => ({ ...current, integration_id: event.target.value }))}
                style={inputStyle}
              >
                <option value="">None (any integration)</option>
                {integrations?.map(i => (
                  <option key={i.id} value={i.id}>{i.name} ({i.provider})</option>
                ))}
              </select>
            </div>

            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Team</label>
              <select
                value={form.team_id}
                onChange={event => setForm(current => ({ ...current, team_id: event.target.value }))}
                style={inputStyle}
              >
                <option value="">None (any team)</option>
                {teams?.map(t => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 22 }}>
            <button type="button" onClick={onClose} style={buttonSecondary}>Cancel</button>
            <button
              type="submit"
              disabled={!canSubmit || submitting}
              style={{ ...buttonPrimary, opacity: !canSubmit || submitting ? 0.6 : 1 }}
            >
              {submitting ? 'Saving…' : submitLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
