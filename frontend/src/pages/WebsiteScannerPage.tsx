import { useState, FormEvent } from 'react';
import { Play, Loader2, AlertCircle, CheckCircle, XCircle, RefreshCw, Shield } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';

interface ScanCheck {
  readonly name: string;
  readonly status: 'passed' | 'failed' | 'warning' | 'info';
  readonly detail: string;
  readonly recommendation: string;
}

interface ScanResult {
  readonly target: string;
  readonly reachable: boolean;
  readonly final_url?: string;
  readonly final_status_code?: number;
  readonly score: number;
  readonly grade: string;
  readonly checks: readonly ScanCheck[];
  readonly scan_duration_ms: number;
  readonly summary: string;
  readonly error?: string;
  readonly message?: string;
}

export function WebsiteScannerPage() {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!url.trim()) return;

    setIsScanning(true);
    setError(null);
    setResult(null);

    try {
      const scanResult = await apiClient.post<ScanResult>('/scanner/website', { url: url.trim() });
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

  const getStatusBadge = (status: ScanCheck['status']) => {
    switch (status) {
      case 'passed':
        return <Badge tone="success"><CheckCircle size={12} className="mr-1" /> Passed</Badge>;
      case 'failed':
        return <Badge tone="danger"><XCircle size={12} className="mr-1" /> Failed</Badge>;
      case 'warning':
        return <Badge tone="warning"><AlertCircle size={12} className="mr-1" /> Warning</Badge>;
      default:
        return <Badge tone="primary"><Shield size={12} className="mr-1" /> Info</Badge>;
    }
  };

  const getGradeBadge = (grade: string) => {
    const tones: Record<string, 'success' | 'primary' | 'warning' | 'danger'> = {
      A: 'success', B: 'primary', C: 'warning', D: 'danger', F: 'danger'
    };
    return <span className="text-lg px-4 py-2"><Badge tone={tones[grade] ?? 'primary'}>{grade}</Badge></span>;
  };

  return (
    <>
      <PageHeader
        eyebrow="Attack surface"
        title="Website Security Scanner"
        description="Inspect a public URL for headers, TLS posture, and common configuration weaknesses."
        actions={<Button variant="secondary" disabled={isScanning}><RefreshCw size={16} /> History</Button>}
      />
      <div className="grid gap-5 xl:grid-cols-[1fr_0.9fr]">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Run analysis</p>
          <form onSubmit={handleScan} className="mt-6 grid gap-4">
            <label className="grid gap-2 text-sm font-medium">
              <span>Target URL</span>
              <input
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={isScanning}
                required
                className="h-11 rounded border bg-surface-low px-3 placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
            </label>
            <Button type="submit" disabled={isScanning || !url.trim()} className="w-full">
              {isScanning ? (
                <> <Loader2 size={16} className="animate-spin mr-2" /> Scanning… </ >
              ) : (
                <> <Play size={16} className="mr-2" /> Start security scan </ >
              )}
            </Button>
            {error && (
              <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded border">
                <AlertCircle size={16} /> {error}
              </div>
            )}
          </form>
        </Card>

        <Card className="p-5">
          {result ? (
            result.reachable ? (
              <>
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm text-on-surface-variant">Overall security score</p>
                    <div className="mt-3 flex items-baseline gap-4">
                      <p className="font-display text-4xl font-bold">{result.score} / 100</p>
                      {getGradeBadge(result.grade)}
                    </div>
                    <p className="mt-2 text-sm text-on-surface-variant">{result.summary}</p>
                  </div>
                  <Badge tone={result.score >= 75 ? 'success' : result.score >= 40 ? 'warning' : 'danger'}>
                    {result.score >= 75 ? 'Low risk' : result.score >= 40 ? 'Medium risk' : 'High risk'}
                  </Badge>
                </div>
                <div className="mt-6 rounded border bg-surface-low p-4">
                  <p className="eyebrow mb-2">Assessment summary</p>
                  <p className="text-sm leading-6 text-on-surface-variant">
                    Scanned <code className="font-mono">{result.final_url || result.target}</code>
                    {result.final_status_code && <span> · HTTP {result.final_status_code}</span>}
                    · {result.scan_duration_ms}ms
                  </p>
                </div>
              </>
            ) : (
              <>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-sm text-on-surface-variant">Scan failed</p>
                    <p className="mt-3 font-display text-3xl font-bold text-destructive">0 / 100</p>
                    <Badge tone="danger">Unreachable</Badge>
                  </div>
                </div>
                <div className="mt-6 rounded border bg-destructive/10 p-4">
                  <p className="eyebrow mb-2 text-destructive">Error</p>
                  <p className="text-sm leading-6 text-on-surface-variant">
                    {result.message || result.error || 'Target could not be scanned.'}
                  </p>
                </div>
              </>
            )
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Overall security score</p>
                  <p className="mt-3 font-display text-3xl font-bold text-on-surface-variant/40">—</p>
                </div>
                <Badge tone="primary">Ready</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Assessment summary</p>
                <p className="text-sm leading-6 text-on-surface-variant">Enter a URL and start a scan to see results.</p>
              </div>
            </>
          )}
        </Card>
      </div>

      {result && result.reachable && (
        <Card className="mt-5">
          <div className="border-b px-5 py-4">
            <p className="font-display font-semibold">Detailed findings</p>
          </div>
          <div className="divide-y p-4">
            {result.checks.map((check, index) => (
              <div key={index} className="flex flex-col gap-2 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                  {getStatusBadge(check.status)}
                  <div>
                    <p className="font-medium">{check.name}</p>
                    <p className="text-sm text-on-surface-variant">{check.detail}</p>
                  </div>
                </div>
                <p className="text-sm text-on-surface-variant max-w-md">{check.recommendation}</p>
              </div>
            ))}
          </div>
        </Card>
      )}
    </>
  );
}