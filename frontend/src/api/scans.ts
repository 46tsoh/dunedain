import client from './client';
import type { Scan, Finding } from '../types';

export const getScans = async (scanType?: string): Promise<Scan[]> => {
  const params: Record<string, string> = { limit: '100' };
  if (scanType) params.scan_type = scanType;
  const { data } = await client.get('/api/scans', { params });
  return data;
};

export const getScan = async (id: string): Promise<Scan> => {
  const { data } = await client.get(`/api/scans/${id}`);
  return data;
};

export const createScan = async (payload: {
  scan_type: string;
  target: string;
  registry_id?: string;
  packages?: Array<{ name: string; version: string; ecosystem: string }>;
  scanner_override?: string;
}): Promise<Scan> => {
  const { data } = await client.post('/api/scans', payload);
  return data;
};

export const getFindings = async (scanId: string): Promise<Finding[]> => {
  const { data } = await client.get(`/api/scans/${scanId}/findings`);
  return data;
};

export const deleteScan = async (scanId: string): Promise<void> => {
  await client.delete(`/api/scans/${scanId}`);
};

export const deleteAllScans = async (): Promise<{ deleted: number }> => {
  const { data } = await client.delete<{ deleted: number }>('/api/scans');
  return data;
};

export const flushQueue = async (): Promise<{ purged: number }> => {
  const { data } = await client.post<{ purged: number }>('/api/scans/queue/flush');
  return data;
};

export const rerunScan = async (scanId: string): Promise<Scan> => {
  const { data } = await client.post<Scan>(`/api/scans/${scanId}/rerun`);
  return data;
};
