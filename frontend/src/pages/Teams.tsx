import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Users, Plus, Trash2, Shield, Globe, Zap } from 'lucide-react';
import { getTeams, createTeam, updateTeam, deleteTeam, createOwnershipRule, deleteOwnershipRule } from '../api/teams';
import { getIntegrations } from '../api/integrations';
import type { Team, OwnershipRule } from '../types';
import { formatDate } from '../utils';

const card = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  padding: '20px 24px',
};

const inputStyle = {
  background: 'var(--bg-primary)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: '8px 12px',
  color: 'var(--text-primary)',
  fontSize: 13,
  width: '100%',
};

const btnPrimary = {
  background: 'var(--accent)',
  color: '#fff',
  border: 'none',
  borderRadius: 6,
  padding: '8px 16px',
  cursor: 'pointer',
  fontWeight: 600,
  fontSize: 13,
};

const btnDanger = {
  background: 'transparent',
  color: 'var(--error)',
  border: '1px solid var(--error)',
  borderRadius: 6,
  padding: '6px 12px',
  cursor: 'pointer',
  fontSize: 12,
};

export default function Teams() {
  const queryClient = useQueryClient();
  const { data: teams, isLoading, error } = useQuery({ queryKey: ['teams'], queryFn: getTeams });
  const { data: integrations } = useQuery({ queryKey: ['integrations'], queryFn: getIntegrations });

  // --- Create Team modal state ---
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newIntegrationId, setNewIntegrationId] = useState<string | null>(null);
  const [newAutoTickets, setNewAutoTickets] = useState(false);
  const [newSevThreshold, setNewSevThreshold] = useState('HIGH');

  // --- Edit Team state ---
  const [editingTeam, setEditingTeam] = useState<Team | null>(null);
  const [editName, setEditName] = useState('');
  const [editDesc, setEditDesc] = useState('');
  const [editEmail, setEditEmail] = useState('');
  const [editIntegrationId, setEditIntegrationId] = useState<string | null>(null);
  const [editAutoTickets, setEditAutoTickets] = useState(false);
  const [editSevThreshold, setEditSevThreshold] = useState('HIGH');

  // --- Add Rule state ---
  const [ruleTeamId, setRuleTeamId] = useState<string | null>(null);
  const [rulePattern, setRulePattern] = useState('');
  const [ruleScanType, setRuleScanType] = useState('');
  const [rulePriority, setRulePriority] = useState('0');
  const [ruleDesc, setRuleDesc] = useState('');

  const createMut = useMutation({
    mutationFn: createTeam,
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['teams'] }); setShowCreate(false); resetCreate(); },
  });

  const updateMut = useMutation({
    mutationFn: (args: { id: string; payload: Parameters<typeof updateTeam>[1] }) => updateTeam(args.id, args.payload),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['teams'] }); setEditingTeam(null); },
  });

  const deleteMut = useMutation({
    mutationFn: deleteTeam,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['teams'] }),
  });

  const addRuleMut = useMutation({
    mutationFn: (args: { teamId: string; payload: Parameters<typeof createOwnershipRule>[1] }) => createOwnershipRule(args.teamId, args.payload),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['teams'] }); setRuleTeamId(null); resetRule(); },
  });

  const deleteRuleMut = useMutation({
    mutationFn: (args: { teamId: string; ruleId: string }) => deleteOwnershipRule(args.teamId, args.ruleId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['teams'] }),
  });

  function resetCreate() {
    setNewName(''); setNewDesc(''); setNewEmail(''); setNewIntegrationId(null); setNewAutoTickets(false); setNewSevThreshold('HIGH');
  }
  function resetRule() {
    setRulePattern(''); setRuleScanType(''); setRulePriority('0'); setRuleDesc('');
  }

  function openEdit(team: Team) {
    setEditingTeam(team);
    setEditName(team.name);
    setEditDesc(team.description || '');
    setEditEmail(team.contact_email || '');
    setEditIntegrationId(team.integration_id);
    setEditAutoTickets(team.auto_create_tickets);
    setEditSevThreshold(team.ticket_severity_threshold || 'HIGH');
  }

  function handleCreate() {
    createMut.mutate({
      name: newName,
      description: newDesc || undefined,
      contact_email: newEmail || undefined,
      integration_id: newIntegrationId,
      auto_create_tickets: newAutoTickets,
      ticket_severity_threshold: newSevThreshold,
    });
  }

  function handleUpdate() {
    if (!editingTeam) return;
    updateMut.mutate({
      id: editingTeam.id,
      payload: {
        name: editName,
        description: editDesc || undefined,
        contact_email: editEmail || undefined,
        integration_id: editIntegrationId,
        auto_create_tickets: editAutoTickets,
        ticket_severity_threshold: editSevThreshold,
      },
    });
  }

  function handleAddRule(teamId: string) {
    addRuleMut.mutate({
      teamId,
      payload: {
        pattern: rulePattern,
        scan_type: ruleScanType || null,
        priority: Number(rulePriority) || 0,
        description: ruleDesc || undefined,
      },
    });
  }

  if (isLoading) return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}>
      <span className="spinner" style={{ width: 32, height: 32 }} />
    </div>
  );

  if (error) return <div className="error-message">Failed to load teams.</div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h1 style={{ fontSize: 24, fontWeight: 700 }}>Teams &amp; Ownership</h1>
        <button style={btnPrimary} onClick={() => setShowCreate(true)}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Plus size={16} /> New Team</span>
        </button>
      </div>

      {/* Create Team Modal */}
      {showCreate && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ ...card, width: 500, maxHeight: '80vh', overflow: 'auto' }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Create Team</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Name *</label>
                <input style={inputStyle} value={newName} onChange={e => setNewName(e.target.value)} placeholder="e.g. Frontend Team" />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Description</label>
                <input style={inputStyle} value={newDesc} onChange={e => setNewDesc(e.target.value)} placeholder="Team description" />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Contact Email</label>
                <input style={inputStyle} value={newEmail} onChange={e => setNewEmail(e.target.value)} placeholder="team@example.com" />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Ticketing Integration</label>
                <select
                  style={{ ...inputStyle, cursor: 'pointer' }}
                  value={newIntegrationId || ''}
                  onChange={e => setNewIntegrationId(e.target.value || null)}
                >
                  <option value="">None</option>
                  {(integrations || []).filter(integration => integration.enabled).map(integration => (
                    <option key={integration.id} value={integration.id}>{integration.name}</option>
                  ))}
                </select>
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-primary)', fontSize: 13, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={newAutoTickets}
                  onChange={e => setNewAutoTickets(e.target.checked)}
                  style={{ accentColor: 'var(--accent)' }}
                />
                Auto-create tickets on scan completion
              </label>
              {newAutoTickets && (
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Minimum Severity for Tickets</label>
                  <select
                    style={{ ...inputStyle, cursor: 'pointer' }}
                    value={newSevThreshold}
                    onChange={e => setNewSevThreshold(e.target.value)}
                  >
                    <option value="CRITICAL">Critical only</option>
                    <option value="HIGH">High + Critical</option>
                    <option value="MEDIUM">Medium and above</option>
                    <option value="LOW">Low and above</option>
                  </select>
                </div>
              )}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
              <button style={{ ...btnDanger, color: 'var(--text-secondary)', borderColor: 'var(--border)' }} onClick={() => { setShowCreate(false); resetCreate(); }}>Cancel</button>
              <button style={btnPrimary} onClick={handleCreate} disabled={!newName.trim()}>Create</button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Team Modal */}
      {editingTeam && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ ...card, width: 500, maxHeight: '80vh', overflow: 'auto' }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Edit Team</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Name</label>
                <input style={inputStyle} value={editName} onChange={e => setEditName(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Description</label>
                <input style={inputStyle} value={editDesc} onChange={e => setEditDesc(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Contact Email</label>
                <input style={inputStyle} value={editEmail} onChange={e => setEditEmail(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Ticketing Integration</label>
                <select
                  style={{ ...inputStyle, cursor: 'pointer' }}
                  value={editIntegrationId || ''}
                  onChange={e => setEditIntegrationId(e.target.value || null)}
                >
                  <option value="">None</option>
                  {(integrations || []).filter(integration => integration.enabled).map(integration => (
                    <option key={integration.id} value={integration.id}>{integration.name}</option>
                  ))}
                </select>
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-primary)', fontSize: 13, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={editAutoTickets}
                  onChange={e => setEditAutoTickets(e.target.checked)}
                  style={{ accentColor: 'var(--accent)' }}
                />
                Auto-create tickets on scan completion
              </label>
              {editAutoTickets && (
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Minimum Severity for Tickets</label>
                  <select
                    style={{ ...inputStyle, cursor: 'pointer' }}
                    value={editSevThreshold}
                    onChange={e => setEditSevThreshold(e.target.value)}
                  >
                    <option value="CRITICAL">Critical only</option>
                    <option value="HIGH">High + Critical</option>
                    <option value="MEDIUM">Medium and above</option>
                    <option value="LOW">Low and above</option>
                  </select>
                </div>
              )}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
              <button style={{ ...btnDanger, color: 'var(--text-secondary)', borderColor: 'var(--border)' }} onClick={() => setEditingTeam(null)}>Cancel</button>
              <button style={btnPrimary} onClick={handleUpdate}>Save</button>
            </div>
          </div>
        </div>
      )}

      {/* Add Rule Modal */}
      {ruleTeamId && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ ...card, width: 460 }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Add Ownership Rule</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Pattern * (glob syntax)</label>
                <input style={inputStyle} value={rulePattern} onChange={e => setRulePattern(e.target.value)} placeholder="e.g. myregistry.io/frontend-*" />
                <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Matched against scan target. Use * and ? as wildcards.</span>
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Scan Type (optional)</label>
                <select
                  style={{ ...inputStyle, cursor: 'pointer' }}
                  value={ruleScanType}
                  onChange={e => setRuleScanType(e.target.value)}
                >
                  <option value="">All types</option>
                  <option value="container">Container</option>
                  <option value="source">Source</option>
                  <option value="dependency">Dependency</option>
                </select>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Priority</label>
                  <input style={inputStyle} type="number" value={rulePriority} onChange={e => setRulePriority(e.target.value)} />
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>Higher wins if multiple match</span>
                </div>
                <div>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Description</label>
                  <input style={inputStyle} value={ruleDesc} onChange={e => setRuleDesc(e.target.value)} />
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
              <button style={{ ...btnDanger, color: 'var(--text-secondary)', borderColor: 'var(--border)' }} onClick={() => { setRuleTeamId(null); resetRule(); }}>Cancel</button>
              <button style={btnPrimary} onClick={() => handleAddRule(ruleTeamId)} disabled={!rulePattern.trim()}>Add Rule</button>
            </div>
          </div>
        </div>
      )}

      {/* Teams List */}
      {(!teams || teams.length === 0) ? (
        <div style={{ ...card, textAlign: 'center', padding: 40 }}>
          <Users size={40} color="var(--text-secondary)" style={{ marginBottom: 12 }} />
          <p style={{ color: 'var(--text-secondary)', marginBottom: 12 }}>No teams configured yet.</p>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>Create a team and add ownership rules to automatically assign scans to teams.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {teams.map(team => (
            <div key={team.id} style={card}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Users size={18} color="var(--accent)" />
                    <Link to={`/teams/${team.id}/dashboard`} style={{ fontSize: 18, fontWeight: 600, color: 'var(--text-primary)' }}>
                      {team.name}
                    </Link>
                    <span style={{
                      background: 'var(--bg-primary)',
                      border: '1px solid var(--border)',
                      borderRadius: 10,
                      padding: '1px 8px',
                      fontSize: 11,
                      color: 'var(--text-secondary)',
                    }}>{team.scan_count} scans</span>
                    {team.auto_create_tickets && (
                      <span style={{
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--accent)',
                        borderRadius: 10,
                        padding: '1px 8px',
                        fontSize: 11,
                        color: 'var(--accent)',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                      }}>
                        <Zap size={11} /> Auto-tickets → {team.integration_name || 'Unknown'} (≥{team.ticket_severity_threshold})
                      </span>
                    )}
                  </div>
                  {team.description && <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>{team.description}</p>}
                  {team.contact_email && <p style={{ color: 'var(--text-secondary)', fontSize: 12, marginTop: 2 }}>{team.contact_email}</p>}
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button style={{ ...btnPrimary, fontSize: 12, padding: '6px 12px' }} onClick={() => openEdit(team)}>Edit</button>
                  <Link to={`/teams/${team.id}/dashboard`} style={{ ...btnPrimary, fontSize: 12, padding: '6px 12px', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Shield size={13} /> Dashboard
                  </Link>
                  <button style={btnDanger} onClick={() => { if (confirm(`Delete team "${team.name}"?`)) deleteMut.mutate(team.id); }}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>

              {/* Ownership Rules */}
              <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <Globe size={13} /> Ownership Rules
                  </span>
                  <button
                    style={{ ...btnPrimary, fontSize: 11, padding: '4px 10px' }}
                    onClick={() => setRuleTeamId(team.id)}
                  >
                    <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><Plus size={12} /> Add Rule</span>
                  </button>
                </div>
                {team.ownership_rules.length === 0 ? (
                  <p style={{ color: 'var(--text-secondary)', fontSize: 12, fontStyle: 'italic' }}>No ownership rules. Scans must be manually assigned.</p>
                ) : (
                  <table style={{ width: '100%', fontSize: 12 }}>
                    <thead>
                      <tr>
                        <th style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--text-secondary)', fontWeight: 500 }}>Pattern</th>
                        <th style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--text-secondary)', fontWeight: 500 }}>Scan Type</th>
                        <th style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--text-secondary)', fontWeight: 500 }}>Priority</th>
                        <th style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--text-secondary)', fontWeight: 500 }}>Description</th>
                        <th style={{ width: 40 }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {team.ownership_rules.map((rule: OwnershipRule) => (
                        <tr key={rule.id}>
                          <td style={{ padding: '4px 8px', fontFamily: 'monospace' }}>{rule.pattern}</td>
                          <td style={{ padding: '4px 8px', color: 'var(--text-secondary)' }}>{rule.scan_type || 'all'}</td>
                          <td style={{ padding: '4px 8px' }}>{rule.priority}</td>
                          <td style={{ padding: '4px 8px', color: 'var(--text-secondary)' }}>{rule.description || '-'}</td>
                          <td style={{ padding: '4px 8px' }}>
                            <button
                              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--error)', padding: 2 }}
                              onClick={() => deleteRuleMut.mutate({ teamId: team.id, ruleId: rule.id })}
                            >
                              <Trash2 size={13} />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 8 }}>
                Created {formatDate(team.created_at)}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
