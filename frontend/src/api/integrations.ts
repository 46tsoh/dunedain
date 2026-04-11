import client from './client';
import type { Integration, Ticket, BulkCreateTicketsResponse, WebhookRegistration, TicketComment } from '../types';

export const getIntegrations = async (): Promise<Integration[]> => {
  const { data } = await client.get<Integration[]>('/api/integrations');
  return data;
};

export const getIntegration = async (id: string): Promise<Integration> => {
  const { data } = await client.get<Integration>(`/api/integrations/${id}`);
  return data;
};

export const createIntegration = async (payload: {
  name: string;
  provider: string;
  enabled?: boolean;
  base_url: string;
  auth_method?: string;
  auth_username?: string | null;
  auth_secret?: string;
  webhook_secret?: string;
  provider_config?: Record<string, unknown>;
  field_mappings?: Array<{
    source: string;
    target_field: string;
    transform?: string | null;
    template_value?: string | null;
    priority?: number;
  }>;
}): Promise<Integration> => {
  const { data } = await client.post<Integration>('/api/integrations', payload);
  return data;
};

export const updateIntegration = async (id: string, payload: Record<string, unknown>): Promise<Integration> => {
  const { data } = await client.put<Integration>(`/api/integrations/${id}`, payload);
  return data;
};

export const deleteIntegration = async (id: string): Promise<void> => {
  await client.delete(`/api/integrations/${id}`);
};

export const testIntegration = async (id: string): Promise<{
  success: boolean;
  message: string;
  projects: Array<{ key: string; name: string }> | null;
}> => {
  const { data } = await client.post(`/api/integrations/${id}/test`);
  return data;
};

export const getIntegrationTickets = async (id: string): Promise<Ticket[]> => {
  const { data } = await client.get<Ticket[]>(`/api/integrations/${id}/tickets`);
  return data;
};

export const createTicket = async (payload: {
  integration_id: string;
  finding_id: string;
  field_overrides?: Record<string, unknown>;
}): Promise<Ticket> => {
  const { data } = await client.post<Ticket>('/api/integrations/tickets', payload);
  return data;
};

export const bulkCreateTickets = async (payload: {
  integration_id: string;
  finding_ids: string[];
  field_overrides?: Record<string, unknown>;
  skip_existing?: boolean;
}): Promise<BulkCreateTicketsResponse> => {
  const { data } = await client.post<BulkCreateTicketsResponse>('/api/integrations/tickets/bulk', payload);
  return data;
};

export const getFindingTickets = async (findingId: string): Promise<Ticket[]> => {
  const { data } = await client.get<Ticket[]>(`/api/integrations/findings/${findingId}/tickets`);
  return data;
};

export const syncTicketStatuses = async (id: string): Promise<{ synced: number }> => {
  const { data } = await client.post(`/api/integrations/${id}/sync-status`);
  return data;
};

// --- Webhook registration ---

export const registerWebhook = async (integrationId: string, payload: {
  callback_url: string;
  jira_events?: string[];
  register_with_jira?: boolean;
  events?: string[];
  register_with_provider?: boolean;
}): Promise<WebhookRegistration> => {
  const { data } = await client.post<WebhookRegistration>(`/api/integrations/${integrationId}/webhooks`, payload);
  return data;
};

export const getWebhookRegistration = async (integrationId: string): Promise<WebhookRegistration | null> => {
  const { data } = await client.get<WebhookRegistration | null>(`/api/integrations/${integrationId}/webhooks`);
  return data;
};

export const deregisterWebhook = async (integrationId: string): Promise<void> => {
  await client.delete(`/api/integrations/${integrationId}/webhooks`);
};

// --- Ticket comments ---

export const getTicketComments = async (ticketId: string): Promise<TicketComment[]> => {
  const { data } = await client.get<TicketComment[]>(`/api/integrations/tickets/${ticketId}/comments`);
  return data;
};

export const addTicketComment = async (ticketId: string, body: string): Promise<TicketComment> => {
  const { data } = await client.post<TicketComment>(`/api/integrations/tickets/${ticketId}/comments`, { body });
  return data;
};
