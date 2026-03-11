import client from './client';
import type { Registry } from '../types';

export const getRegistries = async (): Promise<Registry[]> => {
  const { data } = await client.get('/api/registries/');
  return data;
};

export const getRegistry = async (id: string): Promise<Registry> => {
  const { data } = await client.get(`/api/registries/${id}`);
  return data;
};

export const createRegistry = async (payload: {
  name: string;
  url: string;
  type: string;
  auth_method: string;
  username?: string;
  password?: string;
  auto_sync?: boolean;
}): Promise<Registry> => {
  const { data } = await client.post('/api/registries/', payload);
  return data;
};

export const deleteRegistry = async (id: string): Promise<void> => {
  await client.delete(`/api/registries/${id}`);
};

export const updateRegistry = async (id: string, payload: {
  name?: string;
  url?: string;
  auth_method?: string;
  username?: string;
  password?: string;
  auto_sync?: boolean;
}): Promise<Registry> => {
  const { data } = await client.patch(`/api/registries/${id}`, payload);
  return data;
};

export const testRegistryConnection = async (id: string): Promise<{
  success: boolean;
  message: string;
  repositories: string[] | null;
}> => {
  const { data } = await client.post(`/api/registries/${id}/test`);
  return data;
};

export const syncRegistry = async (id: string): Promise<{ queued: boolean; registry_id: string }> => {
  const { data } = await client.post(`/api/registries/${id}/sync`);
  return data;
};

export const searchRepositories = async (id: string, q: string): Promise<string[]> => {
  const { data } = await client.get(`/api/registries/${id}/repositories/search`, { params: { q } });
  return data;
};

export const listRepositories = async (id: string): Promise<string[]> => {
  const { data } = await client.get(`/api/registries/${id}/repositories`);
  return data;
};

export const listTags = async (id: string, repository: string): Promise<string[]> => {
  const { data } = await client.get(`/api/registries/${id}/repositories/${repository}/tags`);
  return data;
};
