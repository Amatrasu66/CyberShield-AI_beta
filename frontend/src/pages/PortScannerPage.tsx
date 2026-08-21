import { useState, FormEvent } from 'react';
import { Play, Loader2, AlertCircle, Shield, Search, Layers } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card, DataTable } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import { useSlowRequest } from '../hooks/useSlowRequest';
import { SlowRequestNotice } from '../components/SlowRequestNotice';
import type { PortScanResult, PortScanRequest } from '../types';

const QUICK_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 8080];
const COMMON_SCAN_PORTS = [
  1, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 67, 68, 69, 79, 80,
  88, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 199,
  389, 443, 445, 465, 512, 513, 514, 515, 543, 544, 548, 554, 587, 593, 631,
  636, 873, 902, 989, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723,
  2049, 2082, 2083, 2086, 2087, 2121, 2222, 2375, 2376, 2483, 2484, 3000,
  3128, 3306, 3389, 3690, 4000, 4443, 4567, 4786, 5000, 5060, 5061, 5432,
  5601, 5672, 5900, 5984, 6000, 6379, 6443, 6667, 7000, 7001, 8000, 8008,
  8080, 8081, 8086, 8088, 8090, 8140, 8443, 8888, 9000, 9090, 9200, 9300,
  10000, 11211, 15672, 27017, 27018, 27019,
];

type ScanMode = 'quick' | 'common' | 'custom';

export function PortScannerPage() {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState<ScanMode>('quick');
  const [customPorts, setCustomPorts] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<PortScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { run, isSlow, elapsedSeconds } = useSlowRequest();

  const handleScan = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!target.trim()) return;

    setIsScanning(true);
    setError(null);
    setResult(null);

    let requestBody: PortScanRequest = { target: target.trim() };

    if (scanMode === 'quick') {
      requestBody = { ...requestBody, profile: 'quick' };
    } else if (scanMode === 'common') {
      requestBody = { ...requestBody, profile: 'common' };
    } else if (scanMode === 'custom') {
      const ports = customPorts
        .split(',')
        .map((p) => p.trim())
        .filter((p) => p.length > 0)
        .map((p) => parseInt(p, 10))
        .filter((p) => !Number.isNaN(p) && p >= 1 && p <= 65535);
      if (ports.length === 0) {
        setError('Enter at least one valid port number (1-65535).');
        setIsScanning(false);
        return;
      }
      requestBody = { ...requestBody, ports };
    }

    try {
      const scanResult = await run(() => apiClient.post<PortScanResult>('/scanner/ports', requestBody));
      setResult(scanResult);
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message || 'Scan failed. Please try again.');
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsScanning(false);
    }
  };

  const getRiskBadge = (risk: PortScanResult['risk_level']) => {
    const tones: Record<PortScanResult['risk_level'], 'success' | 'primary' | 'warning' | 'danger'> = {
      low: 'success',
      medium: 'warning',
      high: 'danger',
      critical: 'danger',
    };
    const labels: Record<PortScanResult['risk_level'], string> = {
      low: 'Low risk',
      medium: 'Medium risk',
      high: 'High risk',
      critical: 'Critical risk',
    };
    return (
      <Badge tone={tones[risk]}>
        <Shield size={12} className="mr-1" />
        {labels[risk]}
      </Badge>
    );
  };

  const formatBanner = (banner: string) => {
    if (!banner) return '—';
    if (banner.length > 80) return banner.slice(0, 80) + '…';
    return banner;
  };

  const getPortsScanned = () => {
    if (scanMode === 'quick') return QUICK_SCAN_PORTS.length;
    if (scanMode === 'common') return COMMON_SCAN_PORTS.length;
    return customPorts.split(',').filter((p) => p.trim().length > 0).length;
  };

  return (
    <>
      <PageHeader
        eyebrow="Attack surface"
        title="Port Scanner"
        description="Perform a TCP connect scan against a target host to discover open ports and service banners."
        actions={<Button variant="secondary" disabled={isScanning}><Search size={16} /> History</Button>}
      />
      <div className="grid gap-5 xl:grid-cols-[1fr_0.9fr]">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Run scan</p>
          <form onSubmit={handleScan} className="mt-6 grid gap-4">
            <label className="grid gap-2 text-sm font-medium">
              <span>Target</span>
              <input
                type="text"
                placeholder="example.com or 192.0.2.1"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
                required
                className="h-11 rounded border bg-surface-low px-3 placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
            </label>

            <fieldset className="grid gap-3">
              <legend className="text-sm font-medium text-on-surface">Scan mode</legend>
              <div className="grid grid-cols-3 gap-2">
                {(['quick', 'common', 'custom'] as ScanMode[]).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setScanMode(mode)}
                    disabled={isScanning}
                    className={`h-11 rounded border px-3 text-sm font-medium transition focus:outline-none focus:ring-2 focus:ring-primary/60 ${
                      scanMode === mode
                        ? 'border-primary/40 bg-primary/10 text-primary'
                        : 'border-outline-variant/70 bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface'
                    }`}
                  >
                    {mode === 'quick' && 'Quick (20 ports)'}
                    {mode === 'common' && 'Common (100 ports)'}
                    {mode === 'custom' && 'Custom ports'}
                  </button>
                ))}
              </div>
            </fieldset>

            {scanMode === 'custom' && (
              <label className="grid gap-2 text-sm font-medium">
                <span>Custom ports (comma-separated)</span>
                <textarea
                  rows={3}
                  placeholder="22, 80, 443, 8080"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  disabled={isScanning}
                  className="rounded border bg-surface-low p-3 font-mono text-sm text-on-surface placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 resize-none"
                />
                <p className="text-xs leading-5 text-on-surface-variant">
                  Enter up to 100 ports (1-65535). Duplicates will be removed automatically.
                </p>
              </label>
            )}

            <Button type="submit" disabled={isScanning || !target.trim()} className="w-full">
              {isScanning ? (
                <> <Loader2 size={16} className="animate-spin mr-2" /> Scanning… </ >
              ) : (
                <> <Play size={16} className="mr-2" /> Start port scan </ >
              )}
            </Button>

            {isScanning && isSlow && (
              <SlowRequestNotice elapsedSeconds={elapsedSeconds} />
            )}

            {error && (
              <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded border">
                <AlertCircle size={16} /> {error}
              </div>
            )}
          </form>

          <div className="mt-6 rounded border bg-surface-low p-4">
            <p className="eyebrow mb-2">Scan configuration</p>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-on-surface-variant">Target</dt>
              <dd className="font-mono text-on-surface">{target || '—'}</dd>
              <dt className="text-on-surface-variant">Mode</dt>
              <dd className="font-mono text-on-surface capitalize">{scanMode}</dd>
              <dt className="text-on-surface-variant">Ports to scan</dt>
              <dd className="font-mono text-on-surface">{getPortsScanned()}</dd>
              <dt className="text-on-surface-variant">Method</dt>
              <dd className="font-mono text-on-surface">TCP connect</dd>
            </dl>
          </div>
        </Card>

        <Card className="p-5">
          {result ? (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Risk level</p>
                  <div className="mt-3 flex items-baseline gap-4">
                    <p className="font-display text-4xl font-bold">{result.risk_level.toUpperCase()}</p>
                    {getRiskBadge(result.risk_level)}
                  </div>
                  <p className="mt-2 text-sm text-on-surface-variant">{result.summary}</p>
                </div>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Scan summary</p>
                <p className="text-sm leading-6 text-on-surface-variant">
                  Scanned <code className="font-mono">{result.target}</code>
                  {result.resolved_ip && <span> · Resolved to <code className="font-mono">{result.resolved_ip}</code></span>}
                  · {result.scan_duration_ms}ms
                </p>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Risk level</p>
                  <p className="mt-3 font-display text-3xl font-bold text-on-surface-variant/40">—</p>
                </div>
                <Badge tone="primary">Ready</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Scan summary</p>
                <p className="text-sm leading-6 text-on-surface-variant">Enter a target and start a scan to see results.</p>
              </div>
            </>
          )}
        </Card>
      </div>

      {result && (
        <Card className="mt-5">
          <div className="border-b px-5 py-4">
            <p className="font-display font-semibold flex items-center gap-2">
              <Layers size={18} className="text-primary" /> Open ports
            </p>
          </div>
          <div className="p-4">
            {result.open_ports.length > 0 ? (
              <>
                <div className="mb-4 flex flex-wrap gap-2 text-sm text-on-surface-variant">
                  <span className="px-2 py-1 rounded bg-surface-low font-mono">Open: {result.open_ports.filter(p => p.state === 'open').length}</span>
                  <span className="px-2 py-1 rounded bg-surface-low font-mono">Closed: {result.closed_ports}</span>
                  <span className="px-2 py-1 rounded bg-surface-low font-mono">Filtered: {result.filtered_ports}</span>
                </div>
                <DataTable
                  headers={['Port', 'Service', 'State', 'Banner']}
                  rows={result.open_ports.map((p) => [
                    String(p.port),
                    p.service,
                    p.state,
                    formatBanner(p.banner),
                  ])}
                />
              </>
            ) : (
              <div className="text-center py-10">
                <p className="text-sm text-on-surface-variant">No open ports found.</p>
                <p className="mt-1 text-xs text-on-surface-variant/70">All scanned ports were closed or filtered.</p>
              </div>
            )}
          </div>
        </Card>
      )}
    </>
  );
}