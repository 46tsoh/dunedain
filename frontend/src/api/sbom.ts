import client from './client';
import type { SBOM } from '../types';

export const getSBOM = async (scanId: string): Promise<SBOM> => {
  const { data } = await client.get(`/api/scans/${scanId}/sbom`);
  return data;
};
