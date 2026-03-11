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
