import client from './client';

export interface AppSetting {
  key: string;
  value: string;
  description: string | null;
  updated_at: string;
}

export const getSettings = async (): Promise<AppSetting[]> => {
  const { data } = await client.get('/api/settings');
  return data;
};

export const updateSetting = async (key: string, value: string): Promise<AppSetting> => {
  const { data } = await client.put(`/api/settings/${key}`, { value });
  return data;
};
