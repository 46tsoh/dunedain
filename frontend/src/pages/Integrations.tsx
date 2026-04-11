import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertCircle,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  Link2,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Ticket,
  Trash2,
  Webhook,
  X,
} from 'lucide-react';
import {
  createIntegration,
  deleteIntegration,
  getIntegrations,
  testIntegration,
  updateIntegration,
} from '../api/integrations';
import FieldMappingEditor from '../components/FieldMappingEditor';
import type { Integration } from '../types';
import { formatDateTime } from '../utils';
import {
  registerWebhook,
  getWebhookRegistration,
  deregisterWebhook,
} from '../api/integrations';
import { getWebhookEvents, retryWebhookEvent } from '../api/webhooks';
import type { WebhookRegistration, WebhookEvent } from '../types';

type MappingDraft = {
  source: string;
  target_field: string;
  transform: string | null;
  template_value: string | null;
  priority: number;
};

type IntegrationFormState = {
  name: string;
  provider: 'jira' | 'github_issues';
  enabled: boolean;
  base_url: string;
  auth_method: 'api_token' | 'basic' | 'pat';
  auth_username: string;
  auth_secret: string;
  webhook_secret: string;
  project_key: string;
  issue_type: string;
  // GitHub Issues specific
  owner: string;
  repo: string;
  field_mappings: MappingDraft[];
};

type TestResult = {
  success: boolean;
  message: string;
  projects: Array<{ key: string; name: string }> | null;
};

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
  width: 840,
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
  color: '#fff',
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

function emptyForm(): IntegrationFormState {
  return {
    name: '',
    provider: 'jira',
    enabled: true,
    base_url: '',
    auth_method: 'api_token',
    auth_username: '',
    auth_secret: '',
    webhook_secret: '',
    project_key: '',
    issue_type: 'Bug',
    owner: '',
    repo: '',
    field_mappings: [],
  };
}

function toForm(integration: Integration): IntegrationFormState {
  const projectKey = typeof integration.provider_config.project_key === 'string'
    ? integration.provider_config.project_key
    : '';
  const issueType = typeof integration.provider_config.issue_type === 'string'
    ? integration.provider_config.issue_type
    : 'Bug';
  const owner = typeof integration.provider_config.owner === 'string'
    ? integration.provider_config.owner
    : '';
  const repo = typeof integration.provider_config.repo === 'string'
    ? integration.provider_config.repo
    : '';
  const authMethod = integration.auth_method === 'api_token' || integration.auth_method === 'basic' || integration.auth_method === 'pat'
    ? integration.auth_method
    : 'api_token';
  const provider = integration.provider === 'github_issues' ? 'github_issues' : 'jira';

  return {
    name: integration.name,
    provider,
    enabled: integration.enabled,
    base_url: integration.base_url,
    auth_method: authMethod,
    auth_username: integration.auth_username ?? '',
    auth_secret: '',
    webhook_secret: '',
    project_key: projectKey,
    issue_type: issueType,
    owner,
    repo,
    field_mappings: integration.field_mappings
      .map(mapping => ({
        source: mapping.source,
        target_field: mapping.target_field,
        transform: mapping.transform,
        template_value: mapping.template_value,
        priority: mapping.priority,
      }))
      .sort((a, b) => b.priority - a.priority),
  };
}

function IntegrationModal({
  title,
  submitLabel,
  initialForm,
  submitting,
  error,
  onClose,
  onSubmit,
}: {
  title: string;
  submitLabel: string;
  initialForm: IntegrationFormState;
  submitting: boolean;
  error: string;
  onClose: () => void;
  onSubmit: (form: IntegrationFormState) => void;
}) {
  const [form, setForm] = useState<IntegrationFormState>(initialForm);
  const requiresUsername = form.auth_method === 'basic' || (form.provider === 'jira' && form.auth_method === 'api_token');
  const isGitHub = form.provider === 'github_issues';
  const isEditing = title.startsWith('Edit');

  const canSubmit = useMemo(() => {
    if (!form.name.trim()) return false;
    if (!form.base_url.trim()) return false;
    if (requiresUsername && !form.auth_username.trim()) return false;
    if (isGitHub) {
      if (!form.owner.trim()) return false;
      if (!form.repo.trim()) return false;
    } else {
      if (!form.project_key.trim()) return false;
      if (!form.issue_type.trim()) return false;
    }
    return true;
  }, [form, requiresUsername, isGitHub]);

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
              background: 'rgba(239,68,68,0.08)',
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
            onSubmit(form);
          }}
        >
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Name *</label>
              <input
                required
                value={form.name}
                onChange={event => setForm(current => ({ ...current, name: event.target.value }))}
                style={inputStyle}
                placeholder={isGitHub ? 'GitHub Security Issues' : 'Jira Security Tickets'}
              />
            </div>

            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Provider *</label>
              <select
                value={form.provider}
                disabled={isEditing}
                onChange={event => {
                  const provider = event.target.value as IntegrationFormState['provider'];
                  setForm(current => ({
                    ...current,
                    provider,
                    auth_method: provider === 'github_issues' ? 'pat' : current.auth_method === 'pat' && provider === 'jira' ? 'api_token' : current.auth_method,
                    base_url: provider === 'github_issues' && !current.base_url ? 'https://api.github.com' : provider === 'jira' && current.base_url === 'https://api.github.com' ? '' : current.base_url,
                  }));
                }}
                style={{ ...inputStyle, ...(isEditing ? { opacity: 0.6, cursor: 'not-allowed' } : {}) }}
              >
                <option value="jira">Jira</option>
                <option value="github_issues">GitHub Issues</option>
              </select>
            </div>

            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Base URL *</label>
              <input
                required
                value={form.base_url}
                onChange={event => setForm(current => ({ ...current, base_url: event.target.value }))}
                style={inputStyle}
                placeholder={isGitHub ? 'https://api.github.com' : 'https://yourcompany.atlassian.net'}
              />
            </div>

            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Authentication Method *</label>
              <select
                value={form.auth_method}
                onChange={event => setForm(current => ({ ...current, auth_method: event.target.value as IntegrationFormState['auth_method'] }))}
                style={inputStyle}
              >
                {isGitHub ? (
                  <option value="pat">pat</option>
                ) : (
                  <>
                    <option value="api_token">api_token</option>
                    <option value="basic">basic</option>
                    <option value="pat">pat</option>
                  </>
                )}
              </select>
            </div>

            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                Auth Username {requiresUsername ? '*' : '(optional)'}
              </label>
              <input
                value={form.auth_username}
                onChange={event => setForm(current => ({ ...current, auth_username: event.target.value }))}
                style={inputStyle}
                required={requiresUsername}
                placeholder="jira-user@example.com"
              />
            </div>

            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Auth Secret (token/password)</label>
              <input
                type="password"
                value={form.auth_secret}
                onChange={event => setForm(current => ({ ...current, auth_secret: event.target.value }))}
                style={inputStyle}
                placeholder="Leave blank to keep existing secret on edit"
                autoComplete="new-password"
              />
            </div>

            <div style={{ gridColumn: '1 / -1' }}>
              <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Webhook Secret (optional)</label>
              <input
                type="password"
                value={form.webhook_secret}
                onChange={event => setForm(current => ({ ...current, webhook_secret: event.target.value }))}
                style={inputStyle}
                placeholder="HMAC secret for verifying inbound webhooks"
                autoComplete="new-password"
              />
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                Used to verify HMAC signatures on inbound webhook payloads. Leave blank to skip signature verification.
              </div>
            </div>

            {isGitHub ? (
              <>
                <div>
                  <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Repository Owner *</label>
                  <input
                    required
                    value={form.owner}
                    onChange={event => setForm(current => ({ ...current, owner: event.target.value }))}
                    style={inputStyle}
                    placeholder="my-org"
                  />
                </div>

                <div>
                  <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Repository Name *</label>
                  <input
                    required
                    value={form.repo}
                    onChange={event => setForm(current => ({ ...current, repo: event.target.value }))}
                    style={inputStyle}
                    placeholder="security-findings"
                  />
                </div>
              </>
            ) : (
              <>
                <div>
                  <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Jira Project Key *</label>
                  <input
                    required
                    value={form.project_key}
                    onChange={event => setForm(current => ({ ...current, project_key: event.target.value }))}
                    style={inputStyle}
                    placeholder="SEC"
                  />
                </div>

                <div>
                  <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Jira Issue Type *</label>
                  <input
                    required
                    value={form.issue_type}
                    onChange={event => setForm(current => ({ ...current, issue_type: event.target.value }))}
                    style={inputStyle}
                    placeholder="Bug"
                  />
                </div>
              </>
            )}
          </div>

          <div style={{ marginTop: 16, marginBottom: 14 }}>
            <button
              type="button"
              onClick={() => setForm(current => ({ ...current, enabled: !current.enabled }))}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                border: 'none',
                background: 'transparent',
                color: 'var(--text-primary)',
                cursor: 'pointer',
                padding: 0,
              }}
            >
              <span
                style={{
                  width: 34,
                  height: 18,
                  borderRadius: 9,
                  background: form.enabled ? 'var(--success)' : 'var(--border)',
                  position: 'relative',
                  transition: 'background 0.15s',
                }}
              >
                <span
                  style={{
                    position: 'absolute',
                    top: 2,
                    left: form.enabled ? 18 : 2,
                    width: 14,
                    height: 14,
                    borderRadius: '50%',
                    background: '#fff',
                    transition: 'left 0.15s',
                  }}
                />
              </span>
              <span style={{ fontSize: 13 }}>Integration enabled</span>
            </button>
          </div>

          <div style={{ borderTop: '1px solid var(--border)', marginTop: 16, paddingTop: 16 }}>
            <FieldMappingEditor
              mappings={form.field_mappings}
              onChange={field_mappings => setForm(current => ({ ...current, field_mappings }))}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 22 }}>
            <button type="button" onClick={onClose} style={buttonSecondary}>Cancel</button>
            <button type="submit" disabled={!canSubmit || submitting} style={{ ...buttonPrimary, opacity: !canSubmit || submitting ? 0.6 : 1 }}>
              {submitting ? 'Saving…' : submitLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function WebhookSection({ integrationId }: { integrationId: string }) {
  const [showEvents, setShowEvents] = useState(false);
  const [callbackUrl, setCallbackUrl] = useState('');
  const queryClient = useQueryClient();

  const { data: registration, isLoading: loadingReg } = useQuery<WebhookRegistration | null>({
    queryKey: ['webhook-registration', integrationId],
    queryFn: () => getWebhookRegistration(integrationId),
  });

  const { data: events, isLoading: loadingEvents } = useQuery<WebhookEvent[]>({
    queryKey: ['webhook-events', integrationId],
    queryFn: () => getWebhookEvents({ integration_id: integrationId, limit: 20 }),
    enabled: showEvents,
  });

  const registerMut = useMutation({
    mutationFn: () => registerWebhook(integrationId, {
      callback_url: callbackUrl,
      register_with_jira: true,
      register_with_provider: true,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhook-registration', integrationId] });
      setCallbackUrl('');
    },
  });

  const deregisterMut = useMutation({
    mutationFn: () => deregisterWebhook(integrationId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhook-registration', integrationId] });
    },
  });

  const retryMut = useMutation({
    mutationFn: retryWebhookEvent,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhook-events', integrationId] });
    },
  });

  const statusColor = (s: string) => {
    if (s === 'processed') return 'var(--success)';
    if (s === 'failed') return 'var(--error)';
    if (s === 'received') return 'var(--warning)';
    return 'var(--text-secondary)';
  };

  return (
    <div style={{ marginTop: 14, borderTop: '1px solid var(--border)', paddingTop: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <Webhook size={14} color="var(--accent)" />
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>Webhooks</span>
      </div>

      {loadingReg && <span className="spinner" style={{ width: 14, height: 14 }} />}

      {!loadingReg && !registration && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            value={callbackUrl}
            onChange={e => setCallbackUrl(e.target.value)}
            placeholder="https://your-dunedain-host/api/webhooks/{provider}/..."
            style={{ ...inputStyle, flex: 1, marginTop: 0 }}
          />
          <button
            onClick={() => registerMut.mutate()}
            disabled={!callbackUrl.trim() || registerMut.isPending}
            style={{
              ...buttonPrimary,
              padding: '6px 12px',
              fontSize: 12,
              opacity: !callbackUrl.trim() || registerMut.isPending ? 0.6 : 1,
            }}
          >
            {registerMut.isPending ? 'Registering…' : 'Register Webhook'}
          </button>
        </div>
      )}

      {!loadingReg && registration && (
        <div style={{
          background: 'var(--bg-primary)',
          borderRadius: 6,
          padding: '10px 12px',
          border: '1px solid var(--border)',
          fontSize: 12,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>Callback URL</div>
              <div style={{ fontFamily: 'monospace', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                {registration.callback_url}
              </div>
              <div style={{ color: 'var(--text-secondary)', marginTop: 6, display: 'flex', gap: 12 }}>
                <span>Events: {registration.jira_events.join(', ')}</span>
                <span>{registration.external_webhook_id ? 'Auto-registered' : 'Manual'}</span>
                <span>Registered {formatDateTime(registration.created_at)}</span>
              </div>
            </div>
            <button
              onClick={() => deregisterMut.mutate()}
              disabled={deregisterMut.isPending}
              style={{
                ...buttonSecondary,
                padding: '4px 10px',
                fontSize: 11,
                color: 'var(--error)',
              }}
            >
              {deregisterMut.isPending ? 'Removing…' : 'Deregister'}
            </button>
          </div>
        </div>
      )}

      <button
        onClick={() => setShowEvents(v => !v)}
        style={{
          background: 'transparent',
          border: 'none',
          color: 'var(--accent)',
          fontSize: 12,
          cursor: 'pointer',
          marginTop: 10,
          display: 'flex',
          alignItems: 'center',
          gap: 4,
          padding: 0,
        }}
      >
        {showEvents ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        {showEvents ? 'Hide' : 'Show'} Webhook Events
      </button>

      {showEvents && (
        <div style={{ marginTop: 8 }}>
          {loadingEvents && <span className="spinner" style={{ width: 14, height: 14 }} />}
          {events && events.length === 0 && (
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', padding: '8px 0' }}>
              No webhook events received yet.
            </div>
          )}
          {events && events.length > 0 && (
            <table style={{ fontSize: 12 }}>
              <thead>
                <tr>
                  <th>Event Type</th>
                  <th>Issue</th>
                  <th>Status</th>
                  <th>Received</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {events.map(ev => (
                  <tr key={ev.id}>
                    <td style={{ fontFamily: 'monospace' }}>{ev.event_type}</td>
                    <td>{ev.external_issue_key || '—'}</td>
                    <td>
                      <span style={{
                        fontSize: 10,
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: 4,
                        color: statusColor(ev.status),
                        background: `${statusColor(ev.status)}18`,
                        border: `1px solid ${statusColor(ev.status)}40`,
                      }}>
                        {ev.status}
                      </span>
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{formatDateTime(ev.received_at)}</td>
                    <td>
                      {(ev.status === 'failed' || ev.status === 'ignored') && (
                        <button
                          onClick={() => retryMut.mutate(ev.id)}
                          disabled={retryMut.isPending}
                          style={{
                            background: 'transparent',
                            border: '1px solid var(--border)',
                            borderRadius: 4,
                            padding: '2px 6px',
                            fontSize: 11,
                            color: 'var(--accent)',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 3,
                          }}
                        >
                          <RefreshCw size={10} /> Retry
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function parseError(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return fallback;
}

export default function Integrations() {
  const queryClient = useQueryClient();

  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<Integration | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [formError, setFormError] = useState('');
  const [testByIntegrationId, setTestByIntegrationId] = useState<Record<string, TestResult>>({});

  const { data: integrations, isLoading, error } = useQuery({
    queryKey: ['integrations'],
    queryFn: getIntegrations,
  });

  const createMutation = useMutation({
    mutationFn: createIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      setFormError('');
      setShowCreate(false);
    },
    onError: mutationError => {
      setFormError(parseError(mutationError, 'Failed to create integration.'));
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) => updateIntegration(id, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      setFormError('');
      setEditing(null);
    },
    onError: mutationError => {
      setFormError(parseError(mutationError, 'Failed to update integration.'));
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deleteIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      setConfirmDeleteId(null);
    },
  });

  const testMutation = useMutation({
    mutationFn: testIntegration,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
  });

  const submitting = createMutation.isPending || updateMutation.isPending;

  const submitCreate = (form: IntegrationFormState) => {
    setFormError('');
    const providerConfig = form.provider === 'github_issues'
      ? { owner: form.owner, repo: form.repo }
      : { project_key: form.project_key, issue_type: form.issue_type };
    createMutation.mutate({
      name: form.name,
      provider: form.provider,
      enabled: form.enabled,
      base_url: form.base_url,
      auth_method: form.auth_method,
      auth_username: form.auth_username || null,
      auth_secret: form.auth_secret || undefined,
      webhook_secret: form.webhook_secret || undefined,
      provider_config: providerConfig,
      field_mappings: form.field_mappings.map(mapping => ({
        source: mapping.source,
        target_field: mapping.target_field,
        transform: mapping.transform,
        template_value: mapping.template_value,
        priority: mapping.priority,
      })),
    });
  };

  const submitEdit = (form: IntegrationFormState) => {
    if (!editing) return;

    setFormError('');
    const providerConfig = form.provider === 'github_issues'
      ? { owner: form.owner, repo: form.repo }
      : { project_key: form.project_key, issue_type: form.issue_type };
    const payload: Record<string, unknown> = {
      name: form.name,
      enabled: form.enabled,
      base_url: form.base_url,
      auth_method: form.auth_method,
      auth_username: form.auth_username || null,
      provider_config: providerConfig,
      field_mappings: form.field_mappings.map(mapping => ({
        source: mapping.source,
        target_field: mapping.target_field,
        transform: mapping.transform,
        template_value: mapping.template_value,
        priority: mapping.priority,
      })),
    };

    if (form.auth_secret.trim()) {
      payload.auth_secret = form.auth_secret;
    }
    if (form.webhook_secret.trim()) {
      payload.webhook_secret = form.webhook_secret;
    }

    updateMutation.mutate({ id: editing.id, payload });
  };

  const handleTest = (integrationId: string) => {
    setTestByIntegrationId(current => {
      const copy = { ...current };
      delete copy[integrationId];
      return copy;
    });

    testMutation.mutate(integrationId, {
      onSuccess: result => {
        setTestByIntegrationId(current => ({ ...current, [integrationId]: result }));
      },
      onError: mutationError => {
        setTestByIntegrationId(current => ({
          ...current,
          [integrationId]: {
            success: false,
            message: parseError(mutationError, 'Connection test failed.'),
            projects: null,
          },
        }));
      },
    });
  };

  const testingId = testMutation.isPending ? testMutation.variables : null;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700 }}>Integrations</h1>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
            Connect Jira or GitHub Issues to automatically create and sync vulnerability tickets.
          </p>
        </div>

        <button
          onClick={() => {
            setFormError('');
            setShowCreate(true);
          }}
          style={{ ...buttonPrimary, display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Plus size={16} /> New Integration
        </button>
      </div>

      {isLoading && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
          <span className="spinner" />
        </div>
      )}

      {error && <div className="error-message">Failed to load integrations.</div>}

      {integrations && integrations.length === 0 && (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-secondary)' }}>
          <Ticket size={48} style={{ marginBottom: 12, opacity: 0.3 }} />
          <p>No ticketing integrations configured yet.</p>
          <p style={{ fontSize: 12, marginTop: 6 }}>Create a Jira or GitHub Issues integration to start routing findings into tickets.</p>
        </div>
      )}

      {integrations?.map(integration => {
        const testResult = testByIntegrationId[integration.id];
        const isTesting = testingId === integration.id;

        return (
          <div
            key={integration.id}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              padding: 16,
              marginBottom: 12,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 16, fontWeight: 700 }}>{integration.name}</span>
                  <span
                    style={{
                      fontSize: 11,
                      padding: '2px 8px',
                      borderRadius: 4,
                      border: '1px solid rgba(59,130,246,0.35)',
                      color: 'var(--accent)',
                      background: 'rgba(59,130,246,0.1)',
                      textTransform: 'uppercase',
                      fontWeight: 700,
                    }}
                  >
                    {integration.provider.replace('_', ' ')}
                  </span>
                  <span
                    style={{
                      fontSize: 11,
                      padding: '2px 8px',
                      borderRadius: 4,
                      border: `1px solid ${integration.enabled ? 'rgba(52,211,153,0.35)' : 'var(--border)'}`,
                      color: integration.enabled ? 'var(--success)' : 'var(--text-secondary)',
                      background: integration.enabled ? 'rgba(52,211,153,0.1)' : 'var(--bg-primary)',
                    }}
                  >
                    {integration.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>

                <div style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
                  <Link2 size={12} />
                  <span style={{ fontFamily: 'monospace' }}>{integration.base_url}</span>
                </div>

                <div style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <span>{integration.field_mappings.length} field mapping(s)</span>
                  <span>auth: {integration.auth_method}</span>
                  <span>{integration.has_secret ? 'secret configured' : 'no secret configured'}</span>
                  {integration.has_webhook_secret && (
                    <span style={{ color: 'var(--success)' }}>webhook secret configured</span>
                  )}
                  <span>updated {formatDateTime(integration.updated_at)}</span>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                <button
                  onClick={() => handleTest(integration.id)}
                  disabled={isTesting}
                  style={{
                    ...buttonSecondary,
                    padding: '6px 10px',
                    fontSize: 12,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                    opacity: isTesting ? 0.7 : 1,
                  }}
                >
                  {isTesting ? <Loader2 size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <CheckCircle size={13} />}
                  Test Connection
                </button>

                <button
                  onClick={() => {
                    setFormError('');
                    setEditing(integration);
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
                  onClick={() => setConfirmDeleteId(integration.id)}
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

            {testResult && (
              <div
                style={{
                  marginTop: 12,
                  borderRadius: 6,
                  padding: '10px 12px',
                  border: `1px solid ${testResult.success ? 'rgba(52,211,153,0.4)' : 'rgba(239,68,68,0.4)'}`,
                  background: testResult.success ? 'rgba(52,211,153,0.08)' : 'rgba(239,68,68,0.08)',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    color: testResult.success ? 'var(--success)' : 'var(--error)',
                    fontSize: 13,
                    fontWeight: 600,
                  }}
                >
                  {testResult.success ? <CheckCircle size={14} /> : <AlertCircle size={14} />}
                  {testResult.message}
                </div>

                {testResult.projects && testResult.projects.length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>Detected projects:</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {testResult.projects.map(project => (
                        <span
                          key={project.key}
                          style={{
                            fontSize: 11,
                            padding: '3px 8px',
                            borderRadius: 999,
                            border: '1px solid var(--border)',
                            background: 'var(--bg-primary)',
                            color: 'var(--text-primary)',
                          }}
                          title={project.name}
                        >
                          {project.key} · {project.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            <WebhookSection integrationId={integration.id} />
          </div>
        );
      })}

      {showCreate && (
        <IntegrationModal
          title="New Integration"
          submitLabel="Create Integration"
          initialForm={emptyForm()}
          submitting={submitting}
          error={formError}
          onClose={() => {
            if (!submitting) {
              setShowCreate(false);
              setFormError('');
            }
          }}
          onSubmit={submitCreate}
        />
      )}

      {editing && (
        <IntegrationModal
          title="Edit Integration"
          submitLabel="Save Changes"
          initialForm={toForm(editing)}
          submitting={submitting}
          error={formError}
          onClose={() => {
            if (!submitting) {
              setEditing(null);
              setFormError('');
            }
          }}
          onSubmit={submitEdit}
        />
      )}

      {confirmDeleteId && (
        <div style={overlayStyle} onClick={() => setConfirmDeleteId(null)}>
          <div style={{ ...modalStyle, width: 420 }} onClick={event => event.stopPropagation()}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 12 }}>Delete Integration</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: 20, fontSize: 14 }}>
              Are you sure you want to delete this integration? Existing tickets stay in the external system,
              but Dunedain will no longer sync or create tickets for this integration.
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                onClick={() => setConfirmDeleteId(null)}
                style={buttonSecondary}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => deleteMutation.mutate(confirmDeleteId)}
                disabled={deleteMutation.isPending}
                style={{
                  background: 'var(--error)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 6,
                  padding: '8px 16px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  opacity: deleteMutation.isPending ? 0.7 : 1,
                }}
              >
                {deleteMutation.isPending ? 'Deleting…' : 'Delete Integration'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
