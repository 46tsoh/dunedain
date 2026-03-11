import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, X, Trash2, Edit2, ShieldCheck } from 'lucide-react';
import { getPolicies, createPolicy, updatePolicy, deletePolicy } from '../api/policies';
import { formatDate } from '../utils';
import PolicyRuleEditor from '../components/PolicyRuleEditor';
import type { Policy, PolicyRule } from '../types';

const overlayStyle: React.CSSProperties = {
  position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
  display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
};

const modalStyle: React.CSSProperties = {
  background: 'var(--bg-secondary)', border: '1px solid var(--border)',
  borderRadius: 10, padding: 24, width: 560, maxWidth: '95vw', maxHeight: '90vh', overflowY: 'auto',
};

const inputStyle: React.CSSProperties = {
  background: 'var(--bg-primary)', border: '1px solid var(--border)',
  borderRadius: 4, color: 'var(--text-primary)', padding: '8px 12px', width: '100%', marginTop: 4,
};

const emptyForm = { name: '', description: '', action: 'warn' as Policy['action'], enabled: true, rules: [] as PolicyRule[] };

export default function Policies() {
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState<Policy | null>(null);
  const [form, setForm] = useState(emptyForm);
  const qc = useQueryClient();

  const { data: policies, isLoading, error } = useQuery({ queryKey: ['policies'], queryFn: getPolicies });

  const createMutation = useMutation({
    mutationFn: createPolicy,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policies'] }); setShowModal(false); },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Policy> }) => updatePolicy(id, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['policies'] }); setShowModal(false); setEditing(null); },
  });

  const deleteMutation = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['policies'] }),
  });

  const openCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setShowModal(true);
  };

  const openEdit = (p: Policy) => {
    setEditing(p);
    setForm({ name: p.name, description: p.description, action: p.action, enabled: p.enabled, rules: p.rules });
    setShowModal(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editing) {
      updateMutation.mutate({ id: editing.id, data: form });
    } else {
      createMutation.mutate(form);
    }
  };

  const toggleEnabled = (p: Policy) => {
    updateMutation.mutate({ id: p.id, data: { name: p.name, description: p.description, action: p.action, enabled: !p.enabled, rules: p.rules } });
  };

  const actionColors: Record<string, string> = {
    block: 'var(--critical)', warn: 'var(--warning)', audit: 'var(--accent)',
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700 }}>Policies</h1>
        <button onClick={openCreate} style={{
          display: 'flex', alignItems: 'center', gap: 6, background: 'var(--accent)',
          color: '#fff', border: 'none', borderRadius: 6, padding: '8px 16px', fontWeight: 600, cursor: 'pointer',
        }}>
          <Plus size={16} /> New Policy
        </button>
      </div>

      {isLoading && <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><span className="spinner" /></div>}
      {error && <div className="error-message">Failed to load policies.</div>}

      {policies && policies.length === 0 && (
        <div style={{ textAlign: 'center', padding: 60, color: 'var(--text-secondary)' }}>
          <ShieldCheck size={48} style={{ marginBottom: 12, opacity: 0.3 }} />
          <p>No policies yet. Create one to start enforcing security rules.</p>
        </div>
      )}

      {policies && policies.map(p => (
        <div key={p.id} style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
          padding: '16px 20px', marginBottom: 12,
          opacity: p.enabled ? 1 : 0.6,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                <span style={{ fontWeight: 600, fontSize: 16 }}>{p.name}</span>
                <span style={{
                  fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                  background: `${actionColors[p.action]}22`, color: actionColors[p.action],
                }}>{p.action.toUpperCase()}</span>
                {!p.enabled && (
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontStyle: 'italic' }}>Disabled</span>
                )}
              </div>
              <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>{p.description}</p>
              <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginTop: 6 }}>
                {p.rules.length} rule(s) · Updated {formatDate(p.updated_at)}
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {/* Toggle */}
              <button onClick={() => toggleEnabled(p)} style={{
                width: 40, height: 22, borderRadius: 11, border: 'none', cursor: 'pointer',
                background: p.enabled ? 'var(--success)' : 'var(--border)',
                position: 'relative', transition: 'background 0.2s',
              }}>
                <span style={{
                  position: 'absolute', top: 3, width: 16, height: 16, borderRadius: '50%',
                  background: '#fff', transition: 'left 0.2s',
                  left: p.enabled ? 21 : 3,
                }} />
              </button>
              <button onClick={() => openEdit(p)} style={{
                background: 'transparent', border: '1px solid var(--border)', borderRadius: 4,
                color: 'var(--text-secondary)', padding: '5px 10px', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <Edit2 size={13} /> Edit
              </button>
              <button onClick={() => deleteMutation.mutate(p.id)} style={{
                background: 'transparent', border: '1px solid var(--border)', borderRadius: 4,
                color: 'var(--error)', padding: '5px 10px', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <Trash2 size={13} />
              </button>
            </div>
          </div>
        </div>
      ))}

      {showModal && (
        <div style={overlayStyle} onClick={() => setShowModal(false)}>
          <div style={modalStyle} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ fontSize: 18, fontWeight: 700 }}>{editing ? 'Edit Policy' : 'New Policy'}</h2>
              <button onClick={() => setShowModal(false)} style={{ background: 'transparent', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                <X size={20} />
              </button>
            </div>
            <form onSubmit={handleSubmit}>
              <div style={{ marginBottom: 14 }}>
                <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Name *</label>
                <input required value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  style={inputStyle} placeholder="Policy name" />
              </div>
              <div style={{ marginBottom: 14 }}>
                <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Description</label>
                <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  style={{ ...inputStyle, height: 70, resize: 'vertical' }} placeholder="Policy description" />
              </div>
              <div style={{ marginBottom: 14 }}>
                <label style={{ color: 'var(--text-secondary)', fontSize: 12 }}>Action</label>
                <select value={form.action} onChange={e => setForm(f => ({ ...f, action: e.target.value as Policy['action'] }))}
                  style={inputStyle}>
                  <option value="block">Block</option>
                  <option value="warn">Warn</option>
                  <option value="audit">Audit</option>
                </select>
              </div>
              <div style={{ marginBottom: 20 }}>
                <PolicyRuleEditor rules={form.rules} onChange={rules => setForm(f => ({ ...f, rules }))} />
              </div>
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => setShowModal(false)} style={{
                  background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)',
                  borderRadius: 6, padding: '8px 16px', cursor: 'pointer',
                }}>Cancel</button>
                <button type="submit" style={{
                  background: 'var(--accent)', color: '#fff', border: 'none',
                  borderRadius: 6, padding: '8px 16px', fontWeight: 600, cursor: 'pointer',
                }} disabled={createMutation.isPending || updateMutation.isPending}>
                  {editing ? 'Save Changes' : 'Create Policy'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
