import client from './client';
import type { Team, OwnershipRule, TeamDashboardData } from '../types';

export const getTeams = async (): Promise<Team[]> => {
  const { data } = await client.get('/api/teams');
  return data;
};

export const getTeam = async (id: string): Promise<Team> => {
  const { data } = await client.get(`/api/teams/${id}`);
  return data;
};

export const createTeam = async (payload: {
  name: string;
  description?: string;
  contact_email?: string;
  integration_id?: string | null;
  auto_create_tickets?: boolean;
  ticket_severity_threshold?: string;
}): Promise<Team> => {
  const { data } = await client.post('/api/teams', payload);
  return data;
};

export const updateTeam = async (id: string, payload: {
  name?: string;
  description?: string;
  contact_email?: string;
  integration_id?: string | null;
  auto_create_tickets?: boolean;
  ticket_severity_threshold?: string;
}): Promise<Team> => {
  const { data } = await client.put(`/api/teams/${id}`, payload);
  return data;
};

export const deleteTeam = async (id: string): Promise<void> => {
  await client.delete(`/api/teams/${id}`);
};

export const getOwnershipRules = async (teamId: string): Promise<OwnershipRule[]> => {
  const { data } = await client.get(`/api/teams/${teamId}/rules`);
  return data;
};

export const createOwnershipRule = async (teamId: string, payload: {
  pattern: string;
  scan_type?: string | null;
  priority?: number;
  description?: string;
}): Promise<OwnershipRule> => {
  const { data } = await client.post(`/api/teams/${teamId}/rules`, payload);
  return data;
};

export const deleteOwnershipRule = async (teamId: string, ruleId: string): Promise<void> => {
  await client.delete(`/api/teams/${teamId}/rules/${ruleId}`);
};

export interface TeamDashboardFilters {
  severity?: string;
  sla_status?: string;
  is_fixed?: boolean;
}

export const getTeamDashboard = async (teamId: string, filters: TeamDashboardFilters = {}): Promise<TeamDashboardData> => {
  const params: Record<string, string> = {};
  if (filters.severity) params.severity = filters.severity;
  if (filters.sla_status) params.sla_status = filters.sla_status;
  if (filters.is_fixed !== undefined) params.is_fixed = String(filters.is_fixed);
  const { data } = await client.get(`/api/teams/${teamId}/dashboard`, { params });
  return data;
};
