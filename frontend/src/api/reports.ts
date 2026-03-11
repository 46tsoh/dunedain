import client from './client';
import type { DashboardData, AuditLogEntry } from '../types';

export const getDashboard = async (): Promise<DashboardData> => {
  const { data } = await client.get('/api/reports/dashboard');
  return data;
};

export interface AuditLogFilters {
  action?: string;
  resource_type?: string;
  limit?: number;
  skip?: number;
}

export const getAuditLog = async (filters: AuditLogFilters = {}): Promise<AuditLogEntry[]> => {
  const params: Record<string, string | number> = {};
  if (filters.action) params.action = filters.action;
  if (filters.resource_type) params.resource_type = filters.resource_type;
  if (filters.limit !== undefined) params.limit = filters.limit;
  if (filters.skip !== undefined) params.skip = filters.skip;
  const { data } = await client.get('/api/reports/audit-log', { params });
  return data;
};
