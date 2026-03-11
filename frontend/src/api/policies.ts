import client from './client';
import type { Policy, PolicyResult } from '../types';

export const getPolicies = async (): Promise<Policy[]> => {
  const { data } = await client.get('/api/policies');
  return data;
};

export const getPolicy = async (id: string): Promise<Policy> => {
  const { data } = await client.get(`/api/policies/${id}`);
  return data;
};

export const createPolicy = async (payload: Omit<Policy, 'id' | 'created_at' | 'updated_at'>): Promise<Policy> => {
  const { data } = await client.post('/api/policies', payload);
  return data;
};

export const updatePolicy = async (id: string, payload: Partial<Policy>): Promise<Policy> => {
  const { data } = await client.put(`/api/policies/${id}`, payload);
  return data;
};

export const deletePolicy = async (id: string): Promise<void> => {
  await client.delete(`/api/policies/${id}`);
};

export const getPolicyResults = async (scanId: string): Promise<PolicyResult[]> => {
  const { data } = await client.get(`/api/scans/${scanId}/policy-results`);
  return data;
};
