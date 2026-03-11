import { useState, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Plus, X, Trash2, RefreshCw, ChevronDown, ChevronRight,
  Server, Tag, ScanLine, CheckCircle, AlertCircle, Loader, Search,
} from 'lucide-react';
import {
  getRegistries, createRegistry, deleteRegistry, updateRegistry,
  testRegistryConnection, syncRegistry, searchRepositories, listTags,
} from '../api/registries';
import { createScan } from '../api/scans';
import type { Registry } from '../types';
import { formatDateTime } from '../utils';

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const overlayStyle: React.CSSProperties = {
  position: 'fixed', inset: 0,
  background: 'rgba(0,0,0,0.6)',
  display: 'flex', alignItems: 'center', justifyContent: 'center',
  zIndex: 100,
};

const modalStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: 10,
  padding: 24,
  width: 480,
  maxWidth: '95vw',
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

const btnPrimary: React.CSSProperties = {
  background: 'var(--accent)',
  color: '#fff',
  border: 'none',
  borderRadius: 6,
  padding: '8px 16px',
  fontWeight: 600,
  cursor: 'pointer',
};

const iconBtn: React.CSSProperties = {
  background: 'transparent',
  border: 'none',
  color: 'var(--text-secondary)',
  cursor: 'pointer',
  padding: '4px',
  display: 'flex',
  alignItems: 'center',
};

// ---------------------------------------------------------------------------
// Tag row — live-loaded when parent repo is expanded
// ---------------------------------------------------------------------------

interface TagRowProps {
  registryUrl: string;
  registryId: string;
  repository: string;
  tag: string;
}

function TagRow({ registryUrl, registryId, repository, tag }: TagRowProps) {
  const [scanning, setScanning] = useState(false);
  const [queued, setQueued] = useState(false);

  const handleScan = async () => {
    setScanning(true);
    try {
      const imageRef = `${registryUrl}/${repository}:${tag}`;
      await createScan({
        scan_type: 'container',
        target: imageRef,
        registry_id: registryId,
      });
      setQueued(true);
      setTimeout(() => setQueued(false), 3000);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '6px 16px 6px 56px',
      borderTop: '1px solid var(--border)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <Tag size={12} style={{ color: 'var(--text-secondary)', flexShrink: 0 }} />
        <span style={{ fontSize: 13, fontFamily: 'monospace', color: 'var(--text-primary)' }}>{tag}</span>
      </div>
      <button
        onClick={handleScan}
        disabled={scanning || queued}
        title="Scan this image"
        style={{
          ...btnPrimary,
          padding: '3px 10px',
          fontSize: 11,
          display: 'flex', alignItems: 'center', gap: 4,
          opacity: scanning ? 0.6 : 1,
          background: queued ? '#34d399' : 'var(--accent)',
          color: '#fff',
        }}
      >
        {scanning ? <Loader size={11} /> : queued ? <CheckCircle size={11} /> : <ScanLine size={11} />}
        {scanning ? 'Queuing…' : queued ? 'Queued!' : 'Scan'}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Repository row — expands to show tags (fetched live on expand)
// ---------------------------------------------------------------------------

interface RepoRowProps {
  registryId: string;
  registryUrl: string;
  repository: string;
}

function RepoRow({ registryId, registryUrl, repository }: RepoRowProps) {
  const [expanded, setExpanded] = useState(false);

  const { data: tags, isLoading, error } = useQuery({
    queryKey: ['registry-tags', registryId, repository],
    queryFn: () => listTags(registryId, repository),
    enabled: expanded,
    staleTime: 60_000,
  });

  return (
    <div>
      <div
        onClick={() => setExpanded(x => !x)}
        style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 16px 8px 32px',
          borderTop: '1px solid var(--border)',
          cursor: 'pointer',
          userSelect: 'none',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.03)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      >
        <span style={{ width: 14, display: 'flex', alignItems: 'center', color: 'var(--text-secondary)' }}>
          {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </span>
        <Server size={13} style={{ color: '#a78bfa', flexShrink: 0 }} />
        <span style={{ fontSize: 13, fontFamily: 'monospace', color: 'var(--text-primary)' }}>{repository}</span>
        {tags && (
          <span style={{ fontSize: 11, color: 'var(--text-secondary)', marginLeft: 4 }}>
            {tags.length} {tags.length === 1 ? 'tag' : 'tags'}
          </span>
        )}
      </div>

      {expanded && (
        <div>
          {isLoading && (
            <div style={{ padding: '8px 56px', color: 'var(--text-secondary)', fontSize: 12 }}>
              Loading tags…
            </div>
          )}
          {error && (
            <div style={{ padding: '8px 56px', color: 'var(--critical)', fontSize: 12 }}>
              Failed to load tags.
            </div>
          )}
          {tags && tags.length === 0 && (
            <div style={{ padding: '8px 56px', color: 'var(--text-secondary)', fontSize: 12 }}>
              No tags found.
            </div>
          )}
          {tags && tags.map(tag => (
            <TagRow
              key={tag}
              registryUrl={registryUrl}
              registryId={registryId}
              repository={repository}
              tag={tag}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Registry card
// ---------------------------------------------------------------------------

interface RegistryCardProps {
  registry: Registry;
  onDelete: (id: string) => void;
}

function RegistryCard({ registry, onDelete }: RegistryCardProps) {
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Debounce the search query by 400ms
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => setSearchQuery(searchInput.trim()), 400);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [searchInput]);

  const syncMutation = useMutation({
    mutationFn: () => syncRegistry(registry.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['registries'] }),
  });

  const autoSyncMutation = useMutation({
    mutationFn: (value: boolean) => updateRegistry(registry.id, { auto_sync: value }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['registries'] }),
  });

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await testRegistryConnection(registry.id);
      setTestResult(result);
    } catch {
      setTestResult({ success: false, message: 'Request failed.' });
    } finally {
      setTesting(false);
    }
  };

  const { data: searchResults, isLoading: searching, error: searchError } = useQuery({
    queryKey: ['registry-search', registry.id, searchQuery],
    queryFn: () => searchRepositories(registry.id, searchQuery),
    enabled: expanded && searchQuery.length > 0,
    staleTime: 30_000,
  });

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      marginBottom: 12,
      overflow: 'hidden',
    }}>
      {/* Card header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '14px 16px',
        borderBottom: expanded ? '1px solid var(--border)' : 'none',
      }}>
        <div
          onClick={() => setExpanded(x => !x)}
          style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, cursor: 'pointer', userSelect: 'none' }}
        >
          <span style={{ width: 18, display: 'flex', alignItems: 'center', color: 'var(--text-secondary)' }}>
            {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </span>
          <div>
            <div style={{ fontWeight: 700, fontSize: 15 }}>{registry.name}</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2, fontFamily: 'monospace' }}>
              {registry.url}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <span style={{
            fontSize: 11, padding: '2px 8px', borderRadius: 4,
            background: 'rgba(167,139,250,0.12)', color: '#a78bfa',
            border: '1px solid rgba(167,139,250,0.3)',
          }}>
            {registry.type.toUpperCase()}
          </span>
          <span style={{
            fontSize: 11, padding: '2px 8px', borderRadius: 4,
            background: registry.auth_method === 'managed_identity'
              ? 'rgba(52,211,153,0.1)'
              : registry.auth_method === 'username_password'
              ? 'rgba(96,165,250,0.1)'
              : 'rgba(100,116,139,0.1)',
            color: registry.auth_method === 'managed_identity'
              ? '#34d399'
              : registry.auth_method === 'username_password'
              ? '#60a5fa'
              : 'var(--text-secondary)',
            border: `1px solid ${registry.auth_method === 'managed_identity' ? 'rgba(52,211,153,0.3)' : registry.auth_method === 'username_password' ? 'rgba(96,165,250,0.3)' : 'var(--border)'}`,
          }}>
            {registry.auth_method === 'managed_identity' ? 'UAMI' : registry.auth_method === 'username_password' ? `user:${registry.username ?? '?'}` : 'Anonymous'}
          </span>
          {registry.last_synced_at && (
            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              synced {formatDateTime(registry.last_synced_at)}
            </span>
          )}

          {/* Auto-sync toggle */}
          <button
            onClick={() => autoSyncMutation.mutate(!registry.auto_sync)}
            disabled={autoSyncMutation.isPending}
            title={registry.auto_sync ? 'Auto-sync enabled — click to disable' : 'Auto-sync disabled — click to enable'}
            style={{
              display: 'flex', alignItems: 'center', gap: 5,
              background: 'transparent',
              border: '1px solid var(--border)',
              borderRadius: 4,
              padding: '3px 8px',
              cursor: autoSyncMutation.isPending ? 'wait' : 'pointer',
              fontSize: 11,
              color: registry.auto_sync ? '#34d399' : 'var(--text-secondary)',
              opacity: autoSyncMutation.isPending ? 0.6 : 1,
            }}
          >
            {/* Pill switch */}
            <span style={{
              display: 'inline-block',
              width: 26, height: 14,
              borderRadius: 7,
              background: registry.auto_sync ? '#34d399' : 'var(--border)',
              position: 'relative',
              transition: 'background 0.2s',
              flexShrink: 0,
            }}>
              <span style={{
                position: 'absolute',
                top: 2, left: registry.auto_sync ? 14 : 2,
                width: 10, height: 10,
                borderRadius: '50%',
                background: '#fff',
                transition: 'left 0.2s',
              }} />
            </span>
            Auto-sync
          </button>

          <button
            onClick={handleTest}
            disabled={testing}
            title="Test connection"
            style={{
              ...iconBtn,
              fontSize: 11, padding: '3px 8px',
              border: '1px solid var(--border)', borderRadius: 4,
              gap: 4, display: 'flex', alignItems: 'center',
              opacity: testing ? 0.6 : 1,
            }}
          >
            {testing ? <Loader size={11} /> : <CheckCircle size={11} />}
            Test
          </button>

          <button
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending}
            title="Trigger sync"
            style={{
              ...iconBtn,
              fontSize: 11, padding: '3px 8px',
              border: '1px solid var(--border)', borderRadius: 4,
              gap: 4, display: 'flex', alignItems: 'center',
              opacity: syncMutation.isPending ? 0.6 : 1,
            }}
          >
            <RefreshCw size={11} style={{ animation: syncMutation.isPending ? 'spin 1s linear infinite' : 'none' }} />
            Sync
          </button>

          <button onClick={() => onDelete(registry.id)} title="Delete registry" style={iconBtn}>
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Test result banner */}
      {testResult && (
        <div style={{
          padding: '8px 16px', fontSize: 12,
          background: testResult.success ? 'rgba(52,211,153,0.08)' : 'rgba(239,68,68,0.08)',
          color: testResult.success ? '#34d399' : 'var(--critical)',
          borderBottom: expanded ? '1px solid var(--border)' : 'none',
          display: 'flex', alignItems: 'center', gap: 6,
        }}>
          {testResult.success ? <CheckCircle size={12} /> : <AlertCircle size={12} />}
          {testResult.message}
          <button onClick={() => setTestResult(null)} style={{ ...iconBtn, marginLeft: 'auto', padding: 0 }}>
            <X size={12} />
          </button>
        </div>
      )}

      {/* Expanded: search box + results */}
      {expanded && (
        <div>
          {/* Search input */}
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
            <div style={{ position: 'relative' }}>
              <Search size={14} style={{
                position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)',
                color: 'var(--text-secondary)', pointerEvents: 'none',
              }} />
              <input
                autoFocus
                value={searchInput}
                onChange={e => setSearchInput(e.target.value)}
                placeholder="Search repositories… (e.g. nginx, library/redis)"
                style={{
                  ...inputStyle,
                  paddingLeft: 32,
                  marginTop: 0,
                  fontSize: 13,
                }}
              />
            </div>
            {searchQuery.length === 0 && (
              <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6, marginBottom: 0 }}>
                Type to search for repositories. Click a repository to see its tags.
              </p>
            )}
          </div>

          {/* Search results */}
          {searching && (
            <div style={{ padding: '10px 16px', color: 'var(--text-secondary)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Loader size={12} /> Searching…
            </div>
          )}
          {searchError && (
            <div style={{ padding: '10px 16px', color: 'var(--critical)', fontSize: 12 }}>
              Search failed. Check the registry connection.
            </div>
          )}
          {searchResults && searchResults.length === 0 && searchQuery.length > 0 && !searching && (
            <div style={{ padding: '10px 16px', color: 'var(--text-secondary)', fontSize: 12 }}>
              No repositories found for "{searchQuery}".
            </div>
          )}
          {searchResults && searchResults.map(repo => (
            <RepoRow
              key={repo}
              registryId={registry.id}
              registryUrl={registry.url}
              repository={repo}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Add Registry Modal
// ---------------------------------------------------------------------------

interface AddRegistryModalProps {
  onClose: () => void;
  onCreated: () => void;
}

function AddRegistryModal({ onClose, onCreated }: AddRegistryModalProps) {
  const [form, setForm] = useState({
    name: '',
    url: '',
    type: 'docker_hub',
    auth_method: 'username_password',
    username: '',
    password: '',
    auto_sync: true,
  });
  const [error, setError] = useState('');

  const mutation = useMutation({
    mutationFn: createRegistry,
    onSuccess: () => { onCreated(); onClose(); },
    onError: () => setError('Failed to create registry. Please check the details and try again.'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    const payload: Record<string, string | boolean> = {
      name: form.name,
      url: form.url,
      type: form.type,
      auth_method: form.auth_method,
      auto_sync: form.auto_sync,
    };
    if (form.auth_method === 'username_password') {
      payload.username = form.username;
      payload.password = form.password;
    }
    mutation.mutate(payload as Parameters<typeof createRegistry>[0]);
  };

  return (
    <div style={overlayStyle} onClick={onClose}>
      <div style={modalStyle} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>Add Registry</h2>
          <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>
        {error && <div className="error-message" style={{ marginBottom: 16 }}>{error}</div>}
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 14 }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Display Name *</label>
            <input
              required
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              style={inputStyle}
              placeholder="e.g. docker-hub"
            />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Registry URL *</label>
            <input
              required
              value={form.url}
              onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
              style={inputStyle}
              placeholder="e.g. registry-1.docker.io"
            />
            <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
              Hostname only — no https:// prefix.
            </p>
          </div>
          <div style={{ marginBottom: 14 }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Registry Type</label>
            <select
              value={form.type}
              onChange={e => {
                const type = e.target.value;
                setForm(f => ({
                  ...f,
                  type,
                  username: type === 'acr' && f.auth_method === 'username_password'
                    ? '00000000-0000-0000-0000-000000000000'
                    : f.username,
                }));
              }}
              style={inputStyle}
            >
              <option value="docker_hub">Docker Hub</option>
              <option value="acr">Azure Container Registry (ACR)</option>
              <option value="ghcr">GitHub Container Registry</option>
              <option value="generic">Generic (OCI)</option>
            </select>
          </div>
          <div style={{ marginBottom: form.auth_method === 'username_password' ? 14 : 20 }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Authentication</label>
            <select
              value={form.auth_method}
              onChange={e => {
                const auth_method = e.target.value;
                setForm(f => ({
                  ...f,
                  auth_method,
                  username: auth_method === 'username_password' && f.type === 'acr'
                    ? '00000000-0000-0000-0000-000000000000'
                    : auth_method === 'username_password' ? f.username : '',
                }));
              }}
              style={inputStyle}
            >
              <option value="username_password">Username / Password</option>
              <option value="managed_identity">User-Assigned Managed Identity (UAMI)</option>
              <option value="none">Anonymous / Public</option>
            </select>
          </div>
          {form.auth_method === 'username_password' && (
            <>
              <div style={{ marginBottom: 14 }}>
                <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Username *</label>
                <input
                  required
                  value={form.username}
                  onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                  style={inputStyle}
                  placeholder={form.type === 'acr' ? '00000000-0000-0000-0000-000000000000' : 'Username'}
                  autoComplete="username"
                />
              </div>
              <div style={{ marginBottom: 20 }}>
                <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Password / Token *</label>
                <input
                  required
                  type="password"
                  value={form.password}
                  onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                  style={inputStyle}
                  placeholder={form.type === 'acr' ? 'ACR refresh token' : 'Password or access token'}
                  autoComplete="current-password"
                />
                <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                  {form.type === 'acr'
                    ? <>Get a token with: <code style={{ background: 'var(--bg-primary)', padding: '1px 4px', borderRadius: 3 }}>az acr login --name &lt;registry&gt; --expose-token --output tsv --query accessToken</code>. Valid for ~3 hours.</>
                    : 'Use an access token rather than your account password where possible.'}
                </p>
              </div>
            </>
          )}
          {/* Auto-sync toggle */}
          <div style={{ marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              type="button"
              onClick={() => setForm(f => ({ ...f, auto_sync: !f.auto_sync }))}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                background: 'transparent', border: 'none', cursor: 'pointer', padding: 0,
              }}
            >
              <span style={{
                display: 'inline-block', width: 30, height: 16, borderRadius: 8,
                background: form.auto_sync ? '#34d399' : 'var(--border)',
                position: 'relative', transition: 'background 0.2s', flexShrink: 0,
              }}>
                <span style={{
                  position: 'absolute', top: 3, left: form.auto_sync ? 15 : 3,
                  width: 10, height: 10, borderRadius: '50%', background: '#fff',
                  transition: 'left 0.2s',
                }} />
              </span>
            </button>
            <span style={{ fontSize: 13, color: 'var(--text-primary)', cursor: 'pointer' }}
              onClick={() => setForm(f => ({ ...f, auto_sync: !f.auto_sync }))}>
              Enable automatic sync
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
              (scans new tags every 5 min)
            </span>
          </div>
          <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, padding: '8px 16px', cursor: 'pointer' }}
            >
              Cancel
            </button>
            <button type="submit" style={btnPrimary} disabled={mutation.isPending}>
              {mutation.isPending ? 'Adding…' : 'Add Registry'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function Registries() {
  const qc = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const { data: registries, isLoading, error } = useQuery({
    queryKey: ['registries'],
    queryFn: getRegistries,
  });

  const deleteMutation = useMutation({
    mutationFn: deleteRegistry,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['registries'] });
      setConfirmDeleteId(null);
    },
  });

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700 }}>Registries</h1>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
            Browse container registries, scan images, and auto-detect new tags.
          </p>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          style={{ ...btnPrimary, display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Plus size={16} /> Add Registry
        </button>
      </div>

      {isLoading && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}>
          <span className="spinner" />
        </div>
      )}
      {error && <div className="error-message">Failed to load registries.</div>}

      {registries && registries.length === 0 && (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-secondary)' }}>
          <Server size={48} style={{ marginBottom: 12, opacity: 0.3 }} />
          <p>No registries configured. Click "Add Registry" to connect one.</p>
        </div>
      )}

      {registries && registries.map(reg => (
        <RegistryCard
          key={reg.id}
          registry={reg}
          onDelete={id => setConfirmDeleteId(id)}
        />
      ))}

      {/* Add modal */}
      {showAdd && (
        <AddRegistryModal
          onClose={() => setShowAdd(false)}
          onCreated={() => qc.invalidateQueries({ queryKey: ['registries'] })}
        />
      )}

      {/* Delete confirmation */}
      {confirmDeleteId && (
        <div style={overlayStyle} onClick={() => setConfirmDeleteId(null)}>
          <div style={{ ...modalStyle, width: 360 }} onClick={e => e.stopPropagation()}>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 12 }}>Delete Registry</h2>
            <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
              Are you sure you want to remove this registry? Existing scans are not affected.
            </p>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button
                type="button"
                onClick={() => setConfirmDeleteId(null)}
                style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 6, padding: '8px 16px', cursor: 'pointer' }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => deleteMutation.mutate(confirmDeleteId!)}
                disabled={deleteMutation.isPending}
                style={{ background: 'var(--critical)', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 16px', fontWeight: 600, cursor: 'pointer' }}
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
