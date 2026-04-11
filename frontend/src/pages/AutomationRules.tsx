import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { History, Pencil, Play, Plus, Trash2, X, Zap } from 'lucide-react';
import {
  createAutomationRule,
  deleteAutomationRule,
  getAutomationRules,
  getAutomationTriggers,
  getRuleExecutions,
  toggleAutomationRule,
  updateAutomationRule,
} from '../api/automation';
import AutomationRuleEditor from '../components/AutomationRuleEditor';
import type { AutomationRule } from '../types';
import { formatDateTime } from '../utils';

const DEFAULT_TRIGGERS = [
  'jira_status_changed',
  'jira_priority_changed',
  'jira_comment_added',
  'jira_assignee_changed',
  'jira_issue_deleted',
  'ticket_status_changed',
  'ticket_comment_added',
  'ticket_assignee_changed',
  'ticket_deleted',
  'ticket_label_changed',
  'scan_completed',
  'finding_fixed',
  'finding_regressed',
  'policy_violated',
];

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
  width: 420,
  maxWidth: '96vw',
  maxHeight: '92vh',
  overflowY: 'auto',
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

function parseError(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return fallback;
}

function formatTrigger(trigger: string): string {
  return trigger.replace(/_/g, ' ');
}

function RuleHistory({ ruleId }: { ruleId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['automation-executions', ruleId],
    queryFn: () => getRuleExecutions(ruleId, 20),
  });

  return (
    <div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
      {isLoading && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 20 }}>
          <span className="spinner" />
        </div>
      )}

      {error && <div className="error-message">Failed to load execution history.</div>}

      {data && data.length === 0 && (
        <p style={{ color: 'var(--text-secondary)', fontSize: 13, fontStyle: 'italic' }}>
          No executions yet.
        </p>
      )}

      {data?.map(execution => {
        const status = execution.status.toLowerCase();
        const statusColor = status === 'success'
          ? 'var(--success)'
          : status === 'failed'
            ? 'var(--error)'
            : status === 'partial_failure'
              ? 'var(--warning)'
              : 'var(--text-secondary)';

        return (
          <div
            key={execution.id}
            style={{
              border: '1px solid var(--border)',
              borderRadius: 6,
              background: 'var(--bg-primary)',
              marginBottom: 8,
              fontSize: 12,
              padding: '8px 10px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                <Play size={12} />
                <span style={{ color: 'var(--text-primary)' }}>{formatTrigger(execution.trigger_event)}</span>
                <span
                  style={{
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    padding: '2px 6px',
                    color: statusColor,
                    textTransform: 'uppercase',
                    fontWeight: 700,
                    fontSize: 10,
                  }}
                >
                  {status.replace('_', ' ')}
                </span>
              </div>

              <div style={{ color: 'var(--text-secondary)', textAlign: 'right' }}>
                <div>{execution.conditions_matched ? 'conditions matched' : 'conditions not matched'}</div>
                <div>{formatDateTime(execution.created_at)}</div>
              </div>
            </div>

            {execution.conditions_matched && Array.isArray(execution.actions_executed) && execution.actions_executed.length > 0 && (
              <div style={{ marginTop: 6, borderTop: '1px solid var(--border)', paddingTop: 6 }}>
                {execution.actions_executed.map((action, idx) => {
                  if (!action || typeof action !== 'object') return null;
                  const actionType = String(action.action_type ?? 'unknown');
                  const actionSuccess = Boolean(action.success);
                  const detail = String(action.detail ?? '');
                  return (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6,
                        fontSize: 11,
                        color: 'var(--text-secondary)',
                        marginBottom: 2,
                      }}
                    >
                      <span style={{ color: actionSuccess ? 'var(--success)' : 'var(--error)', fontWeight: 700 }}>
                        {actionSuccess ? '\u2713' : '\u2717'}
                      </span>
                      <span>{actionType.replace(/_/g, ' ')}</span>
                      {detail && <span style={{ opacity: 0.7 }}>{'\u2014'} {detail}</span>}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function AutomationRules() {
  const queryClient = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<AutomationRule | null>(null);
  const [expandedHistoryByRuleId, setExpandedHistoryByRuleId] = useState<Record<string, boolean>>({});
  const [confirmDeleteRule, setConfirmDeleteRule] = useState<AutomationRule | null>(null);
  const [formError, setFormError] = useState('');

  const { data: rules, isLoading, error } = useQuery({
    queryKey: ['automation-rules'],
    queryFn: () => getAutomationRules(),
  });

  const { data: triggersData } = useQuery({
    queryKey: ['automation-triggers'],
    queryFn: getAutomationTriggers,
  });

  const createMutation = useMutation({
    mutationFn: createAutomationRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['automation-rules'] });
      setFormError('');
      setShowCreate(false);
    },
    onError: mutationError => {
      setFormError(parseError(mutationError, 'Failed to create automation rule.'));
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ ruleId, payload }: { ruleId: string; payload: Parameters<typeof updateAutomationRule>[1] }) =>
      updateAutomationRule(ruleId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['automation-rules'] });
      setFormError('');
      setEditing(null);
    },
    onError: mutationError => {
      setFormError(parseError(mutationError, 'Failed to update automation rule.'));
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteAutomationRule,
    onSuccess: (_, ruleId) => {
      queryClient.invalidateQueries({ queryKey: ['automation-rules'] });
      queryClient.removeQueries({ queryKey: ['automation-executions', ruleId] });
      setConfirmDeleteRule(null);
    },
  });

  const toggleMutation = useMutation({
    mutationFn: toggleAutomationRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['automation-rules'] });
    },
  });

  const submitting = createMutation.isPending || updateMutation.isPending;
  const triggers = triggersData?.triggers.length ? triggersData.triggers : DEFAULT_TRIGGERS;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700 }}>Automation Rules</h1>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
            Define rules that react to ticket webhooks and internal platform events.
          </p>
        </div>

        <button
          onClick={() => {
            setFormError('');
            setShowCreate(true);
          }}
          style={{ ...buttonPrimary, display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Plus size={16} /> New Rule
        </button>
      </div>

      {isLoading && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
          <span className="spinner" />
        </div>
      )}

      {error && <div className="error-message">Failed to load automation rules.</div>}

      {rules && rules.length === 0 && (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-secondary)' }}>
          <Zap size={48} style={{ marginBottom: 12, opacity: 0.3 }} />
          <p>No automation rules yet.</p>
        </div>
      )}

      {rules?.map(rule => {
        const showHistory = !!expandedHistoryByRuleId[rule.id];

        return (
          <div
            key={rule.id}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              padding: 16,
              marginBottom: 12,
              opacity: rule.enabled ? 1 : 0.7,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 16, fontWeight: 700 }}>{rule.name}</span>
                  <span
                    style={{
                      fontSize: 11,
                      padding: '2px 8px',
                      borderRadius: 4,
                      border: '1px solid var(--accent)',
                      color: 'var(--accent)',
                      background: 'var(--bg-primary)',
                      textTransform: 'uppercase',
                      fontWeight: 700,
                    }}
                  >
                    {formatTrigger(rule.trigger)}
                  </span>
                  <span
                    style={{
                      fontSize: 11,
                      padding: '2px 8px',
                      borderRadius: 4,
                      border: `1px solid ${rule.enabled ? 'var(--success)' : 'var(--border)'}`,
                      color: rule.enabled ? 'var(--success)' : 'var(--text-secondary)',
                      background: 'var(--bg-primary)',
                    }}
                  >
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>

                <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginBottom: 6 }}>
                  {rule.description || 'No description provided.'}
                </p>

                <p style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                  {rule.conditions.length} condition(s) · {rule.actions.length} action(s) · {rule.execution_count} executions · Updated {formatDateTime(rule.updated_at)}
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                <button
                  onClick={() => toggleMutation.mutate(rule.id)}
                  style={{
                    width: 40,
                    height: 22,
                    borderRadius: 11,
                    border: 'none',
                    cursor: 'pointer',
                    background: rule.enabled ? 'var(--success)' : 'var(--border)',
                    position: 'relative',
                    transition: 'background 0.2s',
                  }}
                  title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                >
                  <span
                    style={{
                      position: 'absolute',
                      top: 3,
                      width: 16,
                      height: 16,
                      borderRadius: '50%',
                      background: 'var(--bg-primary)',
                      transition: 'left 0.2s',
                      left: rule.enabled ? 21 : 3,
                    }}
                  />
                </button>

                <button
                  onClick={() => {
                    setExpandedHistoryByRuleId(current => ({ ...current, [rule.id]: !current[rule.id] }));
                  }}
                  style={{
                    ...buttonSecondary,
                    padding: '6px 10px',
                    fontSize: 12,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <History size={13} /> History
                </button>

                <button
                  onClick={() => {
                    setFormError('');
                    setEditing(rule);
                  }}
                  style={{
                    ...buttonSecondary,
                    padding: '6px 10px',
                    fontSize: 12,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <Pencil size={13} /> Edit
                </button>

                <button
                  onClick={() => setConfirmDeleteRule(rule)}
                  style={{
                    ...buttonSecondary,
                    padding: '6px 10px',
                    fontSize: 12,
                    color: 'var(--error)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <Trash2 size={13} /> Delete
                </button>
              </div>
            </div>

            {showHistory && <RuleHistory ruleId={rule.id} />}
          </div>
        );
      })}

      {showCreate && (
        <AutomationRuleEditor
          title="New Automation Rule"
          submitLabel="Create Rule"
          triggers={triggers}
          submitting={submitting}
          error={formError}
          onClose={() => {
            if (!submitting) {
              setShowCreate(false);
              setFormError('');
            }
          }}
          onSubmit={data => {
            setFormError('');
            createMutation.mutate({
              ...data,
              enabled: true,
            });
          }}
        />
      )}

      {editing && (
        <AutomationRuleEditor
          title="Edit Automation Rule"
          submitLabel="Save Changes"
          initialRule={{
            name: editing.name,
            description: editing.description ?? '',
            trigger: editing.trigger,
            conditions: editing.conditions,
            actions: editing.actions,
            integration_id: editing.integration_id ?? '',
            team_id: editing.team_id ?? '',
          }}
          triggers={triggers}
          submitting={submitting}
          error={formError}
          onClose={() => {
            if (!submitting) {
              setEditing(null);
              setFormError('');
            }
          }}
          onSubmit={data => {
            setFormError('');
            updateMutation.mutate({
              ruleId: editing.id,
              payload: {
                ...data,
                enabled: editing.enabled,
              },
            });
          }}
        />
      )}

      {confirmDeleteRule && (
        <div style={overlayStyle} onClick={() => setConfirmDeleteRule(null)}>
          <div style={modalStyle} onClick={event => event.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700 }}>Delete Rule</h2>
              <button
                onClick={() => setConfirmDeleteRule(null)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <p style={{ color: 'var(--text-secondary)', marginBottom: 20, fontSize: 14 }}>
              Are you sure you want to delete <strong>{confirmDeleteRule.name}</strong>? This will remove the rule and its execution history.
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                onClick={() => setConfirmDeleteRule(null)}
                style={buttonSecondary}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => deleteMutation.mutate(confirmDeleteRule.id)}
                disabled={deleteMutation.isPending}
                style={{
                  background: 'var(--error)',
                  color: 'var(--text-primary)',
                  border: 'none',
                  borderRadius: 6,
                  padding: '8px 16px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  opacity: deleteMutation.isPending ? 0.7 : 1,
                }}
              >
                {deleteMutation.isPending ? 'Deleting…' : 'Delete Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
