import client from './client';
import type { AutomationRule, AutomationRuleExecution } from '../types';

export const getAutomationTriggers = async (): Promise<{ triggers: string[] }> => {
  const { data } = await client.get<{ triggers: string[] }>('/api/automation/triggers');
  return data;
};

export const getAutomationRules = async (params?: {
  trigger?: string;
  enabled?: boolean;
  integration_id?: string;
}): Promise<AutomationRule[]> => {
  const { data } = await client.get<AutomationRule[]>('/api/automation/rules', { params });
  return data;
};

export const createAutomationRule = async (payload: {
  name: string;
  description?: string | null;
  enabled?: boolean;
  trigger: string;
  conditions?: Array<Record<string, unknown>>;
  actions?: Array<Record<string, unknown>>;
  integration_id?: string | null;
  team_id?: string | null;
}): Promise<AutomationRule> => {
  const { data } = await client.post<AutomationRule>('/api/automation/rules', payload);
  return data;
};

export const getAutomationRule = async (ruleId: string): Promise<AutomationRule> => {
  const { data } = await client.get<AutomationRule>(`/api/automation/rules/${ruleId}`);
  return data;
};

export const updateAutomationRule = async (ruleId: string, payload: {
  name?: string;
  description?: string | null;
  enabled?: boolean;
  trigger?: string;
  conditions?: Array<Record<string, unknown>>;
  actions?: Array<Record<string, unknown>>;
  integration_id?: string | null;
  team_id?: string | null;
}): Promise<AutomationRule> => {
  const { data } = await client.put<AutomationRule>(`/api/automation/rules/${ruleId}`, payload);
  return data;
};

export const deleteAutomationRule = async (ruleId: string): Promise<void> => {
  await client.delete(`/api/automation/rules/${ruleId}`);
};

export const toggleAutomationRule = async (ruleId: string): Promise<AutomationRule> => {
  const { data } = await client.post<AutomationRule>(`/api/automation/rules/${ruleId}/toggle`);
  return data;
};

export const getRuleExecutions = async (ruleId: string, limit?: number): Promise<AutomationRuleExecution[]> => {
  const { data } = await client.get<AutomationRuleExecution[]>(
    `/api/automation/rules/${ruleId}/executions`,
    { params: limit ? { limit } : undefined },
  );
  return data;
};

export const getRecentExecutions = async (limit?: number): Promise<AutomationRuleExecution[]> => {
  const { data } = await client.get<AutomationRuleExecution[]>(
    '/api/automation/executions/recent',
    { params: limit ? { limit } : undefined },
  );
  return data;
};
