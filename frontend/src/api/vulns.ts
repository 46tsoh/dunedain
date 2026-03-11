import client from './client';
import type { OsvVulnerability } from '../types';

export const getVulnDetail = async (vulnId: string): Promise<OsvVulnerability> => {
  const { data } = await client.get(`/api/vulns/${vulnId}`);
  return data;
};
