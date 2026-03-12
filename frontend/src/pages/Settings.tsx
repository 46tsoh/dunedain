import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getSettings, updateSetting } from '../api/settings';
import { formatDateTime } from '../utils';

const SCANNER_OPTIONS = [
  {
    value: 'auto',
    label: 'Auto',
    description: 'Try Trivy first, fall back to Grype, then OSV-only. Recommended.',
  },
  {
    value: 'trivy',
    label: 'Trivy',
    description: 'Always use Trivy for scanning. Falls back to OSV-only if Trivy is unavailable.',
  },
  {
    value: 'grype',
    label: 'Grype',
    description: 'Always use Grype for scanning. Falls back to OSV-only if Grype is unavailable.',
  },
  {
    value: 'syft_grype',
    label: 'Syft + Grype',
    description: 'Registry-native scanning: Syft fetches only the manifest and needed layers via the registry API (no full image pull), generates an SBOM, then Grype scans it offline. Best for registry-sourced container scans.',
  },
  {
    value: 'osv_scanner',
    label: 'OSV-Scanner',
    description: 'Use Google\'s osv-scanner CLI to scan container images directly against the OSV vulnerability database. Handles multi-platform images natively.',
  },
];

const WINDOWS_SCANNER_OPTIONS = [
  {
    value: 'pe_version',
    label: 'PE Version (default)',
    description:
      'Infers the OS build from PE DLL productVersion fields extracted by Syft. ' +
      'Fast — no full layer download required.',
  },
  {
    value: 'layer_extraction',
    label: 'Layer Extraction',
    description:
      'Downloads all image layers from the registry, extracts the filesystem, and parses ' +
      'the Windows SOFTWARE registry hive for the exact OS build and cumulative update revision. ' +
      'More accurate OS CVE matching but slower (~5–10 min for large base images).',
  },
];

const WINDOWS_BACKEND_OPTIONS = [
  {
    value: 'grype',
    label: 'Grype (default)',
    description:
      'Feeds a Syft-generated SBOM into Grype for CVE matching. ' +
      'Strong coverage of .NET, NuGet, and PE binary packages.',
    disabled: false,
  },
  {
    value: 'trivy',
    label: 'Trivy — Coming Soon',
    description:
      'Native Windows image scanning via Trivy. Not yet supported on Linux hosts — ' +
      'Trivy cannot interpret Windows package formats from extracted layers without a Windows daemon.',
    disabled: true,
  },
];

const COMPARISON_OPTIONS = [
  {
    value: 'none',
    label: 'Disabled',
    description: 'No comparison scan. Each container scan runs with the primary engine only.',
  },
  {
    value: 'auto',
    label: 'Auto',
    description: 'Trivy first, fall back to Grype, then OSV-only.',
  },
  {
    value: 'trivy',
    label: 'Trivy',
    description: 'Run a side-by-side Trivy scan alongside the primary scan.',
  },
  {
    value: 'grype',
    label: 'Grype',
    description: 'Run a side-by-side Grype scan alongside the primary scan.',
  },
  {
    value: 'syft_grype',
    label: 'Syft + Grype',
    description: 'Run a side-by-side Syft + Grype registry-native scan alongside the primary scan.',
  },
  {
    value: 'osv_scanner',
    label: 'OSV-Scanner',
    description: 'Run a side-by-side osv-scanner container scan alongside the primary scan.',
  },
];

const SLA_FIELDS = [
  { key: 'sla_critical_hours', label: 'Critical', color: 'var(--critical)' },
  { key: 'sla_high_hours', label: 'High', color: 'var(--high)' },
  { key: 'sla_medium_hours', label: 'Medium', color: 'var(--medium)' },
  { key: 'sla_low_hours', label: 'Low', color: 'var(--low)' },
] as const;

const CVSS_THRESHOLD_FIELDS = [
  { key: 'sla_cvss_critical_min', label: 'Critical min CVSS', color: 'var(--critical)', placeholder: '9.0' },
  { key: 'sla_cvss_high_min', label: 'High min CVSS', color: 'var(--high)', placeholder: '7.0' },
  { key: 'sla_cvss_medium_min', label: 'Medium min CVSS', color: 'var(--medium)', placeholder: '4.0' },
] as const;

interface AppSetting {
  key: string;
  value: string;
  description: string | null;
  updated_at: string;
}

function SlaSection({ settings, isLoading }: { settings: AppSetting[]; isLoading: boolean }) {
  const queryClient = useQueryClient();
  const mutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: string }) => updateSetting(key, value),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['settings'] }),
  });

  // Local draft state so the user can type before saving
  const [drafts, setDrafts] = useState<Record<string, string>>({});

  const getValue = (key: string) => {
    if (key in drafts) return drafts[key];
    return settings.find(s => s.key === key)?.value ?? '';
  };

  const isDirty = (key: string) => {
    const saved = settings.find(s => s.key === key)?.value ?? '';
    return key in drafts && drafts[key] !== saved;
  };

  const save = (key: string) => {
    const val = getValue(key);
    mutation.mutate({ key, value: val });
    setDrafts(d => { const next = { ...d }; delete next[key]; return next; });
  };

  const currentMode = getValue('sla_mode') || 'severity';
  const isCvss = currentMode === 'cvss';

  const handleModeChange = (mode: string) => {
    mutation.mutate({ key: 'sla_mode', value: mode });
  };

  // In CVSS mode, derive labels from current threshold values
  const cvssLabels = isCvss ? (() => {
    const critMin = getValue('sla_cvss_critical_min') || '9.0';
    const highMin = getValue('sla_cvss_high_min') || '7.0';
    const medMin = getValue('sla_cvss_medium_min') || '4.0';
    return [
      `CVSS >= ${critMin}`,
      `CVSS >= ${highMin}`,
      `CVSS >= ${medMin}`,
      `CVSS < ${medMin}`,
    ];
  })() : null;

  const sectionStyle: React.CSSProperties = {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    padding: 24,
    marginTop: 16,
    marginBottom: 8,
  };

  const radioStyle = (selected: boolean): React.CSSProperties => ({
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    padding: '10px 14px',
    borderRadius: 8,
    border: selected ? '2px solid var(--accent)' : '1px solid var(--border)',
    background: selected ? 'rgba(59,130,246,0.08)' : 'var(--bg-primary)',
    cursor: 'pointer',
    fontSize: 13,
    fontWeight: selected ? 600 : 400,
    color: selected ? 'var(--accent)' : 'var(--text-primary)',
    transition: 'border-color 0.15s, background 0.15s',
  });

  const radioDot = (selected: boolean): React.CSSProperties => ({
    width: 16,
    height: 16,
    borderRadius: '50%',
    border: selected ? '2px solid var(--accent)' : '2px solid var(--border)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    flexShrink: 0,
  });

  return (
    <section style={sectionStyle}>
      <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
        Global SLA Deadlines
      </h2>
      <p style={{ color: 'var(--text-secondary)', fontSize: 14, marginBottom: 20 }}>
        Remediation deadlines applied to all findings. Choose whether tiers are determined by
        finding severity or by CVSS score ranges.
      </p>

      {isLoading ? (
        <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>Loading...</div>
      ) : (
        <div>
          {/* Mode toggle */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
            <button style={radioStyle(!isCvss)} onClick={() => handleModeChange('severity')}>
              <div style={radioDot(!isCvss)}>
                {!isCvss && <div style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent)' }} />}
              </div>
              By Severity
            </button>
            <button style={radioStyle(isCvss)} onClick={() => handleModeChange('cvss')}>
              <div style={radioDot(isCvss)}>
                {isCvss && <div style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--accent)' }} />}
              </div>
              By CVSS Score
            </button>
            {mutation.isPending && mutation.variables?.key === 'sla_mode' && (
              <span style={{ fontSize: 12, color: 'var(--text-secondary)', alignSelf: 'center' }}>Saving...</span>
            )}
          </div>

          {/* CVSS threshold inputs — only shown in CVSS mode */}
          {isCvss && (
            <div style={{ marginBottom: 20 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10 }}>
                CVSS Score Thresholds
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 12 }}>
                Findings with CVSS score at or above each threshold are assigned that tier.
                Scores below the medium threshold use the low tier.
                Findings without a CVSS score fall back to severity-based lookup.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                {CVSS_THRESHOLD_FIELDS.map(({ key, label, color, placeholder }) => {
                  const dirty = isDirty(key);
                  const saving = mutation.isPending && mutation.variables?.key === key;
                  return (
                    <div key={key} style={{
                      background: 'var(--bg-primary)',
                      border: dirty ? '2px solid var(--accent)' : '1px solid var(--border)',
                      borderRadius: 8,
                      padding: 12,
                    }}>
                      <div style={{ fontSize: 11, fontWeight: 600, color, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
                        {label}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <input
                          type="number"
                          min={0}
                          max={10}
                          step={0.1}
                          value={getValue(key)}
                          onChange={e => setDrafts(d => ({ ...d, [key]: e.target.value }))}
                          onKeyDown={e => { if (e.key === 'Enter' && dirty) save(key); }}
                          placeholder={placeholder}
                          style={{
                            background: 'var(--bg-secondary)',
                            border: '1px solid var(--border)',
                            borderRadius: 4,
                            color: 'var(--text-primary)',
                            padding: '5px 8px',
                            width: 70,
                            fontSize: 13,
                            fontWeight: 600,
                          }}
                        />
                      </div>
                      {dirty && (
                        <button
                          onClick={() => save(key)}
                          disabled={saving}
                          style={{
                            marginTop: 6, fontSize: 11, fontWeight: 600,
                            background: 'var(--accent)', color: '#fff', border: 'none',
                            borderRadius: 4, padding: '3px 10px', cursor: 'pointer',
                            opacity: saving ? 0.6 : 1,
                          }}
                        >
                          {saving ? 'Saving...' : 'Save'}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Hour inputs */}
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10 }}>
            Remediation Deadlines
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
            {SLA_FIELDS.map(({ key, label, color }, idx) => {
              const dirty = isDirty(key);
              const saving = mutation.isPending && mutation.variables?.key === key;
              const displayLabel = cvssLabels ? cvssLabels[idx] : label;
              return (
                <div key={key} style={{
                  background: 'var(--bg-primary)',
                  border: dirty ? '2px solid var(--accent)' : '1px solid var(--border)',
                  borderRadius: 8,
                  padding: 16,
                }}>
                  <div style={{
                    fontSize: 12, fontWeight: 600, color, textTransform: 'uppercase',
                    letterSpacing: '0.05em', marginBottom: 8,
                  }}>
                    {displayLabel}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <input
                      type="number"
                      min={0}
                      value={getValue(key)}
                      onChange={e => setDrafts(d => ({ ...d, [key]: e.target.value }))}
                      onKeyDown={e => { if (e.key === 'Enter' && dirty) save(key); }}
                      style={{
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--border)',
                        borderRadius: 4,
                        color: 'var(--text-primary)',
                        padding: '6px 10px',
                        width: 80,
                        fontSize: 14,
                        fontWeight: 600,
                      }}
                    />
                    <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>hours</span>
                  </div>
                  {dirty && (
                    <button
                      onClick={() => save(key)}
                      disabled={saving}
                      style={{
                        marginTop: 8, fontSize: 12, fontWeight: 600,
                        background: 'var(--accent)', color: '#fff', border: 'none',
                        borderRadius: 4, padding: '4px 12px', cursor: 'pointer',
                        opacity: saving ? 0.6 : 1,
                      }}
                    >
                      {saving ? 'Saving...' : 'Save'}
                    </button>
                  )}
                  {mutation.isError && mutation.variables?.key === key && (
                    <div style={{ fontSize: 12, color: 'var(--critical)', marginTop: 4 }}>
                      Failed to save.
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {settings.some(s => SLA_FIELDS.some(f => f.key === s.key)) && (
        <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 14 }}>
          Last updated: {formatDateTime(
            settings
              .filter(s => SLA_FIELDS.some(f => f.key === s.key))
              .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime())[0]
              ?.updated_at
          )}
        </p>
      )}
    </section>
  );
}

export default function Settings() {
  const queryClient = useQueryClient();

  const { data: settings, isLoading, isError } = useQuery({
    queryKey: ['settings'],
    queryFn: getSettings,
  });

  const mutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: string }) =>
      updateSetting(key, value),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
    },
  });

  const scannerSetting = settings?.find((s) => s.key === 'scanner_backend');
  const currentScanner = scannerSetting?.value ?? 'auto';

  const comparisonSetting = settings?.find((s) => s.key === 'comparison_backend');
  const currentComparison = comparisonSetting?.value ?? 'none';

  const windowsModeSetting = settings?.find((s) => s.key === 'windows_scanner_mode');
  const currentWindowsMode = windowsModeSetting?.value ?? 'pe_version';

  const windowsBackendSetting = settings?.find((s) => s.key === 'windows_scanner_backend');
  const currentWindowsBackend = windowsBackendSetting?.value ?? 'grype';

  const renderOptions = (
    options: typeof SCANNER_OPTIONS,
    currentValue: string,
    settingKey: string,
  ) => (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {options.map((opt) => {
        const isDisabled = Boolean('disabled' in opt && (opt as { disabled?: boolean }).disabled);
        const isSelected = currentValue === opt.value;
        const isSaving = mutation.isPending && mutation.variables?.key === settingKey && mutation.variables?.value === opt.value;
        return (
          <button
            key={opt.value}
            disabled={isDisabled}
            onClick={() => {
              if (!isSelected && !isDisabled) {
                mutation.mutate({ key: settingKey, value: opt.value });
              }
            }}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 14,
              padding: '14px 16px',
              borderRadius: 8,
              border: isSelected
                ? '2px solid var(--accent)'
                : '1px solid var(--border)',
              background: isSelected
                ? 'rgba(59,130,246,0.08)'
                : 'var(--bg-primary)',
              cursor: isDisabled ? 'not-allowed' : isSelected ? 'default' : 'pointer',
              textAlign: 'left',
              transition: 'border-color 0.15s, background 0.15s',
              opacity: isDisabled ? 0.45 : isSaving ? 0.6 : 1,
            }}
          >
            {/* Radio circle */}
            <div style={{
              width: 18,
              height: 18,
              borderRadius: '50%',
              border: isSelected ? '2px solid var(--accent)' : '2px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              marginTop: 2,
            }}>
              {isSelected && (
                <div style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: 'var(--accent)',
                }} />
              )}
            </div>
            <div>
              <div style={{
                fontWeight: 600,
                fontSize: 14,
                color: isSelected ? 'var(--accent)' : 'var(--text-primary)',
                marginBottom: 2,
              }}>
                {opt.label}
                {isSaving && <span style={{ fontWeight: 400, marginLeft: 8, fontSize: 13 }}>Saving…</span>}
              </div>
              <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                {opt.description}
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );

  const sectionStyle: React.CSSProperties = {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 10,
    padding: 24,
    marginBottom: 16,
  };

  return (
    <div style={{ maxWidth: 1100 }}>
      <h1 style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
        Settings
      </h1>
      <p style={{ color: 'var(--text-secondary)', marginBottom: 32 }}>
        Platform configuration. Changes take effect on the next scan.
      </p>

      {isError && (
        <div style={{
          background: 'rgba(239,68,68,0.1)',
          border: '1px solid rgba(239,68,68,0.3)',
          borderRadius: 8,
          padding: '12px 16px',
          color: '#ef4444',
          marginBottom: 24,
        }}>
          Failed to load settings.
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, alignItems: 'start' }}>

        {/* Left column — Linux */}
        <div>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
            Linux / General
          </p>

          <section style={sectionStyle}>
            <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
              Scanner Engine
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 14, marginBottom: 20 }}>
              Vulnerability scanner used for container and source scans.
              Trivy, Grype, and Syft are all installed in this deployment.
            </p>
            {isLoading ? (
              <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>Loading…</div>
            ) : (
              renderOptions(SCANNER_OPTIONS, currentScanner, 'scanner_backend')
            )}
            {scannerSetting && (
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 14 }}>
                Last updated: {formatDateTime(scannerSetting.updated_at)}
              </p>
            )}
            {mutation.isError && mutation.variables?.key === 'scanner_backend' && (
              <p style={{ fontSize: 13, color: '#ef4444', marginTop: 12 }}>Failed to save. Please try again.</p>
            )}
          </section>

          <section style={sectionStyle}>
            <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
              Comparison Engine
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 14, marginBottom: 20 }}>
              When enabled, every container scan also enqueues a second scan using this engine
              so you can compare findings side by side. No effect on dependency or source scans.
            </p>
            {isLoading ? (
              <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>Loading…</div>
            ) : (
              renderOptions(COMPARISON_OPTIONS, currentComparison, 'comparison_backend')
            )}
            {comparisonSetting && (
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 14 }}>
                Last updated: {formatDateTime(comparisonSetting.updated_at)}
              </p>
            )}
            {mutation.isError && mutation.variables?.key === 'comparison_backend' && (
              <p style={{ fontSize: 13, color: '#ef4444', marginTop: 12 }}>Failed to save. Please try again.</p>
            )}
          </section>
        </div>

        {/* Right column — Windows */}
        <div>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 12 }}>
            Windows
          </p>

          <section style={sectionStyle}>
            <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
              Scan Mode
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 14, marginBottom: 20 }}>
              How Windows container images are scanned. Applies whenever a Windows-only image is detected,
              regardless of the Linux scanner selected on the left.
            </p>
            {isLoading ? (
              <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>Loading…</div>
            ) : (
              renderOptions(WINDOWS_SCANNER_OPTIONS, currentWindowsMode, 'windows_scanner_mode')
            )}
            {windowsModeSetting && (
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 14 }}>
                Last updated: {formatDateTime(windowsModeSetting.updated_at)}
              </p>
            )}
            {mutation.isError && mutation.variables?.key === 'windows_scanner_mode' && (
              <p style={{ fontSize: 13, color: '#ef4444', marginTop: 12 }}>Failed to save. Please try again.</p>
            )}
          </section>

          <section style={sectionStyle}>
            <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
              Scanner Engine
            </h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: 14, marginBottom: 20 }}>
              CVE-matching engine for Windows scans. Fully independent from the Linux scanner.
            </p>
            {isLoading ? (
              <div style={{ color: 'var(--text-secondary)', fontSize: 14 }}>Loading…</div>
            ) : (
              renderOptions(WINDOWS_BACKEND_OPTIONS, currentWindowsBackend, 'windows_scanner_backend')
            )}
            {windowsBackendSetting && (
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 14 }}>
                Last updated: {formatDateTime(windowsBackendSetting.updated_at)}
              </p>
            )}
            {mutation.isError && mutation.variables?.key === 'windows_scanner_backend' && (
              <p style={{ fontSize: 13, color: '#ef4444', marginTop: 12 }}>Failed to save. Please try again.</p>
            )}
          </section>
        </div>
      </div>

      {/* Global SLA Deadlines */}
      <SlaSection settings={settings ?? []} isLoading={isLoading} />

      {/* Data persistence note */}
      <section style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 10, padding: 24, marginTop: 8 }}>
        <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
          Data Persistence
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: 14, lineHeight: 1.6 }}>
          Scan results, findings, policies, and settings are stored in a SQLite database
          at <code style={{ background: 'var(--bg-primary)', padding: '1px 6px', borderRadius: 4, fontSize: 13 }}>/data/dunedain.db</code> inside
          the backend container, backed by the <code style={{ background: 'var(--bg-primary)', padding: '1px 6px', borderRadius: 4, fontSize: 13 }}>dunedain-data</code> Docker volume.
          Data persists across container restarts. To back up, copy the volume's contents or snapshot
          the database file directly.
        </p>
      </section>
    </div>
  );
}
