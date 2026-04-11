interface Scan {
  id: string;
  name: string;
  scan_type: 'container' | 'dependency' | 'source';
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'unsupported';
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
  scan_duration_seconds: number | null;
  scanner_engine: string | null;
  scanner_override: string | null;
  base_image: string | null;
  base_image_chain: string[] | null;
  registry_id: string | null;
  registry_name: string | null;
  team_id: string | null;
  team_name: string | null;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  negligible_count: number;
  unknown_count: number;
}

interface Finding {
  id: string;
  scan_id: string;
  package_name: string;
  package_version: string;
  package_ecosystem: string;
  vulnerability_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEGLIGIBLE' | 'UNKNOWN';
  cvss_score: number | null;
  description: string;
  fix_version: string | null;
  is_fixed: boolean;
  reachable: boolean;
  exploitable: boolean;
  risk_score: number;
  aliases: string[];
  references: string[];
}

interface Policy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rules: PolicyRule[];
  action: 'block' | 'warn' | 'audit';
  created_at: string;
  updated_at: string;
}

interface PolicyRule {
  type: 'severity_threshold' | 'cvss_threshold' | 'fix_available' | 'package_blocklist';
  min_severity?: string;
  min_score?: number;
  require_fix?: boolean;
  packages?: string[];
  action?: string;
}

interface DashboardData {
  total_scans: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  negligible_count: number;
  unknown_count: number;
  recent_scans: Scan[];
  top_vulnerabilities: Array<{vulnerability_id: string; count: number; severity: string}>;
}

interface SBOMComponent {
  name: string;
  version: string;
  purl: string | null;
  licenses: string[];
  ecosystem: string;
}

interface SBOM {
  id: string;
  scan_id: string;
  format: string;
  spec_version: string;
  content: Record<string, unknown>;
  components_count: number;
  components: SBOMComponent[];
  generated_at: string;
}

interface PolicyResult {
  id: string;
  scan_id: string;
  policy_id: string;
  policy_name: string;
  passed: boolean;
  status: 'pass' | 'fail' | 'warn';
  violations: Array<{rule: string; message: string; affected_findings: string[]}>;
  evaluated_at: string;
}

interface AuditLogEntry {
  id: string;
  created_at: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  details: Record<string, unknown>;
}

interface OsvAffectedPackage {
  package: { name: string; ecosystem: string; purl?: string };
  ranges?: Array<{
    type: string;
    events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
  }>;
  versions?: string[];
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  modified?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: OsvAffectedPackage[];
  references?: Array<{ type: string; url: string }>;
  database_specific?: {
    severity?: string;
    cwe_ids?: string[];
    [key: string]: unknown;
  };
}

interface Registry {
  id: string;
  name: string;
  url: string;
  type: 'acr' | 'docker_hub' | 'ghcr' | 'generic';
  auth_method: 'managed_identity' | 'username_password' | 'none';
  auto_sync: boolean;
  username: string | null;
  created_at: string;
  last_synced_at: string | null;
  repository_cache: Record<string, string[]> | null;
}

interface OwnershipRule {
  id: string;
  team_id: string;
  pattern: string;
  scan_type: string | null;
  priority: number;
  description: string | null;
  created_at: string;
}

interface Team {
  id: string;
  name: string;
  description: string | null;
  contact_email: string | null;
  integration_id: string | null;
  auto_create_tickets: boolean;
  ticket_severity_threshold: string;
  integration_name: string | null;
  created_at: string;
  updated_at: string;
  ownership_rules: OwnershipRule[];
  scan_count: number;
}

interface TeamFindingSummary {
  finding_id: string;
  vulnerability_id: string;
  package_name: string;
  package_version: string;
  severity: string;
  cvss_score: number | null;
  risk_score: number;
  is_fixed: boolean;
  fix_version: string | null;
  discovered_at: string;
  first_seen_at: string | null;
  scan_id: string;
  scan_name: string;
  target: string | null;
  sla_hours: number | null;
  hours_elapsed: number;
  sla_violated: boolean;
}

interface TeamDashboardData {
  team: Team;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  sla_violations: number;
  findings: TeamFindingSummary[];
}

export interface IntegrationFieldMapping {
  id: string;
  integration_id: string;
  source: string;
  target_field: string;
  transform: string | null;
  template_value: string | null;
  priority: number;
}

export interface Integration {
  id: string;
  name: string;
  provider: 'jira' | 'servicenow' | 'linear' | 'github_issues';
  enabled: boolean;
  base_url: string;
  auth_method: string;
  auth_username: string | null;
  has_secret: boolean;
  has_webhook_secret: boolean;
  provider_config: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  field_mappings: IntegrationFieldMapping[];
}

export interface Ticket {
  id: string;
  integration_id: string;
  finding_id: string | null;
  external_id: string;
  external_key: string;
  external_url: string;
  external_status: string | null;
  external_assignee: string | null;
  external_priority: string | null;
  summary: string;
  created_at: string;
  synced_at: string | null;
}

export interface BulkCreateTicketsResponse {
  created: Ticket[];
  skipped: string[];
  errors: Array<{ finding_id: string; error: string }>;
}

export interface WebhookEvent {
  id: string;
  integration_id: string;
  event_type: string;
  external_issue_id: string | null;
  external_issue_key: string | null;
  status: string;
  error_message: string | null;
  received_at: string;
  processed_at: string | null;
}

export interface WebhookEventDetail extends WebhookEvent {
  payload: Record<string, unknown>;
}

export interface WebhookRegistration {
  id: string;
  integration_id: string;
  external_webhook_id: string | null;
  callback_url: string;
  jira_events: string[];
  is_cloud: boolean;
  created_at: string;
  updated_at: string;
}

export interface TicketComment {
  id: string;
  ticket_id: string;
  external_comment_id: string | null;
  author: string | null;
  body: string;
  direction: 'inbound' | 'outbound';
  created_at: string;
}

export interface AutomationRule {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  trigger: string;
  conditions: Array<Record<string, unknown>>;
  actions: Array<Record<string, unknown>>;
  integration_id: string | null;
  team_id: string | null;
  execution_count: number;
  last_executed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AutomationRuleExecution {
  id: string;
  rule_id: string;
  trigger_event: string;
  trigger_context: Record<string, unknown>;
  conditions_matched: boolean;
  actions_executed: Array<Record<string, unknown>>;
  status: string;
  created_at: string;
}

export type {
  Scan,
  Finding,
  Policy,
  PolicyRule,
  DashboardData,
  SBOMComponent,
  SBOM,
  PolicyResult,
  AuditLogEntry,
  OsvVulnerability,
  OsvAffectedPackage,
  Registry,
  Team,
  OwnershipRule,
  TeamFindingSummary,
  TeamDashboardData,
};
