import client from './client';
import type { WebhookEvent, WebhookEventDetail } from '../types';

export const getWebhookEvents = async (params?: {
  integration_id?: string;
  status?: string;
  skip?: number;
  limit?: number;
}): Promise<WebhookEvent[]> => {
  const { data } = await client.get<WebhookEvent[]>('/api/webhooks/events', { params });
  return data;
};

export const getWebhookEvent = async (eventId: string): Promise<WebhookEventDetail> => {
  const { data } = await client.get<WebhookEventDetail>(`/api/webhooks/events/${eventId}`);
  return data;
};

export const retryWebhookEvent = async (eventId: string): Promise<{ event_id: string; status: string }> => {
  const { data } = await client.post(`/api/webhooks/events/${eventId}/retry`);
  return data;
};
