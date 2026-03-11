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

export type { Scan, Finding, Policy, PolicyRule, DashboardData, SBOMComponent, SBOM, PolicyResult, AuditLogEntry, OsvVulnerability, OsvAffectedPackage, Registry };
