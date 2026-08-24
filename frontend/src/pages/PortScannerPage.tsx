import { useState, FormEvent, useCallback } from 'react';
import { Play, Loader2, AlertCircle, Shield, Search, Layers, Clock, Target, HardDrive, ArrowLeft, ChevronLeft, ChevronRight, Eye, History, Globe, Building, Flag, AlertTriangle, CheckCircle, HelpCircle, Activity, Zap } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card, DataTable } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import { useSlowRequest } from '../hooks/useSlowRequest';
import { SlowRequestNotice } from '../components/SlowRequestNotice';
import type { PortScanResult, PortScanRequest, PortScanHistoryItem, PortScanDetail, IPReputationResult, ThreatAssessment } from '../types';

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

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function ReputationBadge({ reputation }: { reputation: IPReputationResult['reputation'] }) {
  const config: Record<string, { tone: 'success' | 'warning' | 'danger' | 'primary'; label: string; icon: typeof Shield }> = {
    clean: { tone: 'success', label: 'CLEAN', icon: CheckCircle },
    malicious: { tone: 'danger', label: 'MALICIOUS', icon: AlertTriangle },
    suspicious: { tone: 'warning', label: 'SUSPICIOUS', icon: AlertCircle },
    unknown: { tone: 'primary', label: 'UNKNOWN', icon: HelpCircle },
    unavailable: { tone: 'primary', label: 'UNAVAILABLE', icon: HelpCircle },
  };
  const c = config[reputation] ?? config.unknown;
  const Icon = c.icon;
  return <Badge tone={c.tone}><Icon size={12} className="mr-1" />{c.label}</Badge>;
}

function ConfidenceBadge({ confidence }: { confidence: string | null }) {
  if (!confidence || confidence === 'none') return <Badge tone="primary">unknown</Badge>;
  const toneMap: Record<string, 'success' | 'warning' | 'danger' | 'primary'> = {
    low: 'primary',
    medium: 'warning',
    high: 'danger',
    very_high: 'danger',
  };
  return <Badge tone={toneMap[confidence] ?? 'primary'}>{confidence}</Badge>;
}

function ThreatLevelBadge({ level }: { level: ThreatAssessment['level'] }) {
  const tones: Record<ThreatAssessment['level'], 'success' | 'primary' | 'warning' | 'danger'> = {
    low: 'success',
    medium: 'warning',
    high: 'danger',
    critical: 'danger',
  };
  const icons: Record<ThreatAssessment['level'], typeof Shield> = {
    low: CheckCircle,
    medium: AlertCircle,
    high: AlertTriangle,
    critical: Zap,
  };
  const Icon = icons[level];
  return <Badge tone={tones[level]}><Icon size={12} className="mr-1" />{level.toUpperCase()}</Badge>;
}

function ThreatConfidenceBadge({ confidence }: { confidence: ThreatAssessment['confidence'] }) {
  const tones: Record<ThreatAssessment['confidence'], 'success' | 'primary' | 'warning' | 'danger'> = {
    high: 'success',
    medium: 'warning',
    low: 'danger',
  };
  return <Badge tone={tones[confidence] ?? 'primary'}>{confidence}</Badge>;
}

function IPReputationCard({ reputation, titleEyebrow }: { reputation: IPReputationResult | null | undefined; titleEyebrow?: string }) {
  if (!reputation) {
    return (
      <Card className="p-5">
        <p className="eyebrow mb-2">{titleEyebrow ?? 'IP reputation'}</p>
        <div className="flex items-start gap-3 rounded border bg-surface-low p-4">
          <HelpCircle size={18} className="mt-0.5 text-on-surface-variant" />
          <div>
            <p className="text-sm font-medium text-on-surface">Reputation not available for this scan.</p>
            <p className="mt-1 text-sm leading-6 text-on-surface-variant">This scan was created before IP reputation was enabled or the provider returned no data.</p>
          </div>
        </div>
      </Card>
    );
  }

  const isUnavailable = reputation.reputation === 'unavailable';
  const isUnknown = reputation.reputation === 'unknown';

  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="eyebrow mb-2">{titleEyebrow ?? 'IP reputation'}</p>
          <p className="text-xs font-mono uppercase tracking-wide text-on-surface-variant">Independent from port risk</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <p className="font-display text-2xl font-bold">{reputation.reputation.toUpperCase()}</p>
            <ReputationBadge reputation={reputation.reputation} />
            {!isUnavailable && !isUnknown && <ConfidenceBadge confidence={reputation.confidence} />}
          </div>
          <p className="mt-2 text-sm text-on-surface-variant">
            {isUnavailable && 'Provider unavailable or IP not checked.'}
            {isUnknown && 'No reputation data reported for this IP.'}
            {reputation.reputation === 'clean' && 'No abuse reported for this IP.'}
            {reputation.reputation === 'suspicious' && `${reputation.reports} abuse report${reputation.reports === 1 ? '' : 's'} • flagged as suspicious.`}
            {reputation.reputation === 'malicious' && `${reputation.reports} abuse report${reputation.reports === 1 ? '' : 's'} • flagged as malicious.`}
          </p>
        </div>
        <Badge tone="primary"><Globe size={12} className="mr-1" />{reputation.provider}</Badge>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded border bg-surface-low p-4">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Globe size={14} /> IP</p>
          <p className="mt-2 font-mono text-sm font-semibold text-on-surface">{reputation.ip}</p>
          <p className="mt-1 text-xs text-on-surface-variant">Reports: {reputation.reports}</p>
        </div>
        <div className="rounded border bg-surface-low p-4">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Flag size={14} /> Country / ASN</p>
          <p className="mt-2 font-mono text-sm font-semibold text-on-surface">{reputation.country ?? '—'} {reputation.asn ? `· AS${reputation.asn}` : ''}</p>
          <p className="mt-1 text-xs text-on-surface-variant">ASN: {reputation.asn ?? '—'}</p>
        </div>
        <div className="rounded border bg-surface-low p-4">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Building size={14} /> Organization</p>
          <p className="mt-2 text-sm font-semibold text-on-surface">{reputation.organization ?? reputation.isp ?? '—'}</p>
          <p className="mt-1 text-xs text-on-surface-variant">{reputation.isp ?? ''}</p>
        </div>
        <div className="rounded border bg-surface-low p-4">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Clock size={14} /> Last reported</p>
          <p className="mt-2 text-sm font-semibold text-on-surface">{reputation.last_reported_at ? formatDate(reputation.last_reported_at) : '—'}</p>
          <p className="mt-1 text-xs text-on-surface-variant">Checked: {reputation.checked_at ? formatDate(reputation.checked_at) : '—'}</p>
        </div>
      </div>

      {reputation.reason && isUnavailable && (
        <p className="mt-4 text-xs font-mono text-on-surface-variant/70">Reason: {reputation.reason}</p>
      )}
    </Card>
  );
}

function ThreatAssessmentCard({ assessment, titleEyebrow }: { assessment: ThreatAssessment | null | undefined; titleEyebrow?: string }) {
  if (!assessment) {
    return (
      <Card className="p-5">
        <p className="eyebrow mb-2">{titleEyebrow ?? 'Overall threat'}</p>
        <div className="flex items-start gap-3 rounded border bg-surface-low p-4">
          <HelpCircle size={18} className="mt-0.5 text-on-surface-variant" />
          <div>
            <p className="text-sm font-medium text-on-surface">Threat assessment not available for this scan.</p>
            <p className="mt-1 text-sm leading-6 text-on-surface-variant">This scan was created before overall threat assessment was enabled.</p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="eyebrow mb-2">{titleEyebrow ?? 'Overall threat'}</p>
          <p className="text-xs font-mono uppercase tracking-wide text-on-surface-variant">Derived from port risk + IP reputation</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <p className="font-display text-2xl font-bold">{assessment.score} / 100</p>
            <ThreatLevelBadge level={assessment.level} />
            <ThreatConfidenceBadge confidence={assessment.confidence} />
          </div>
          <p className="mt-2 text-sm leading-6 text-on-surface-variant">{assessment.explanation}</p>
        </div>
        <Badge tone="primary"><Activity size={12} className="mr-1" />{assessment.confidence}</Badge>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-3">
        <div className="rounded border bg-surface-low p-4">
          <p className="text-xs font-medium uppercase tracking-wide text-on-surface-variant">Overall Score</p>
          <p className="mt-2 font-display text-xl font-bold">{assessment.score}</p>
          <p className="mt-1 text-xs text-on-surface-variant">Level: {assessment.level}</p>
        </div>
        <div className="rounded border bg-surface-low p-4">
          <p className="text-xs font-medium uppercase tracking-wide text-on-surface-variant">Confidence</p>
          <p className="mt-2 font-display text-xl font-bold capitalize">{assessment.confidence}</p>
          <p className="mt-1 text-xs text-on-surface-variant">Evidence completeness</p>
        </div>
        <div className="rounded border bg-surface-low p-4">
          <p className="text-xs font-medium uppercase tracking-wide text-on-surface-variant">Assessed</p>
          <p className="mt-2 font-mono text-sm font-semibold">{formatDate(assessment.assessed_at)}</p>
          <p className="mt-1 text-xs text-on-surface-variant">{assessment.factors.length} factor(s)</p>
        </div>
      </div>

      {assessment.factors.length > 0 && (
        <div className="mt-6">
          <p className="eyebrow mb-2">Contributing factors</p>
          <div className="space-y-2">
            {assessment.factors.map((f, idx) => (
              <div key={`${f.type}-${idx}`} className="flex items-center justify-between gap-3 rounded border bg-surface-low px-3 py-2">
                <div>
                  <p className="text-sm font-medium capitalize">{f.type.replace(/_/g, ' ')}</p>
                  <p className="text-xs text-on-surface-variant">{f.description}</p>
                </div>
                <Badge tone={f.weight > 0 ? 'warning' : 'primary'}>+{f.weight}</Badge>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

export function PortScannerPage() {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState<ScanMode>('quick');
  const [customPorts, setCustomPorts] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<PortScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { run, isSlow, elapsedSeconds } = useSlowRequest();

  // History state
  const [showHistory, setShowHistory] = useState(false);
  const [history, setHistory] = useState<PortScanHistoryItem[] | null>(null);
  const [historyMeta, setHistoryMeta] = useState<{ total: number; page: number; limit: number } | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyPage, setHistoryPage] = useState(1);
  const historyLimit = 20;
  const { run: runHistory, isSlow: historySlow, elapsedSeconds: historyElapsed } = useSlowRequest();

  // Detail state
  const [detail, setDetail] = useState<PortScanDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const { run: runDetail, isSlow: detailSlow, elapsedSeconds: detailElapsed } = useSlowRequest();

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
      if (showHistory) {
        setHistoryPage(1);
        void fetchHistory(1);
      }
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

  const getHistoryRiskBadge = (risk: PortScanHistoryItem['risk_level']) => {
    const tones: Record<string, 'success' | 'primary' | 'warning' | 'danger'> = {
      low: 'success',
      medium: 'warning',
      high: 'danger',
      critical: 'danger',
    };
    return <Badge tone={tones[risk] ?? 'primary'}>{risk}</Badge>;
  };

  const getStatusBadge = (status: PortScanHistoryItem['status']) => {
    if (status === 'completed') return <Badge tone="success">completed</Badge>;
    if (status === 'failed') return <Badge tone="danger">failed</Badge>;
    return <Badge tone="primary">{status}</Badge>;
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

  const getHistoryErrorMessage = (err: unknown, fallback: string): string => {
    if (err instanceof ApiClientError) {
      if (err.status === 401) return 'Your session has expired. Please sign in again.';
      if (err.status === 503) return 'History is temporarily unavailable. Please try again later.';
      if (err.status === 0) return 'Unable to connect to the backend. Check your connection and try again.';
      return err.message || fallback;
    }
    return fallback;
  };

  const fetchHistory = useCallback(async (page: number) => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const { data, meta } = await runHistory(() =>
        apiClient.getWithMeta<PortScanHistoryItem[]>(`/scanner/ports/history?page=${page}&limit=${historyLimit}`),
      );
      setHistory(data);
      if (meta) {
        setHistoryMeta({
          total: (meta.total as number) ?? data.length,
          page: (meta.page as number) ?? page,
          limit: (meta.limit as number) ?? historyLimit,
        });
      } else {
        setHistoryMeta({ total: data.length, page, limit: historyLimit });
      }
      setHistoryPage(page);
    } catch (err) {
      setHistoryError(getHistoryErrorMessage(err, 'Unable to load scan history. Please try again.'));
    } finally {
      setHistoryLoading(false);
    }
  }, [runHistory]);

  const handleToggleHistory = () => {
    if (showHistory) {
      setShowHistory(false);
      setDetail(null);
      setDetailError(null);
    } else {
      setShowHistory(true);
      setDetail(null);
      setDetailError(null);
      void fetchHistory(1);
    }
  };

  const handleViewDetail = async (scanId: string) => {
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);
    try {
      const data = await runDetail(() => apiClient.get<PortScanDetail>(`/scanner/ports/history/${encodeURIComponent(scanId)}`));
      setDetail(data);
    } catch (err) {
      if (err instanceof ApiClientError) {
        if (err.status === 401) setDetailError('Your session has expired. Please sign in again.');
        else if (err.status === 404) setDetailError('Scan not found. It may have been deleted or you do not have access.');
        else if (err.status === 0) setDetailError('Unable to connect to the backend. Check your connection and try again.');
        else setDetailError(err.message || 'Unable to load scan detail.');
      } else {
        setDetailError('An unexpected error occurred.');
      }
    } finally {
      setDetailLoading(false);
    }
  };

  const totalPages = historyMeta ? Math.max(1, Math.ceil(historyMeta.total / historyMeta.limit)) : 1;

  return (
    <>
      <PageHeader
        eyebrow="Attack surface"
        title="Port Scanner"
        description="Perform a TCP connect scan against a target host to discover open ports and service banners."
        actions={
          <Button variant="secondary" onClick={handleToggleHistory} disabled={isScanning && !showHistory}>
            {showHistory ? <ArrowLeft size={16} /> : <Search size={16} />}
            {showHistory ? 'Back to scanner' : 'History'}
          </Button>
        }
      />

      {!showHistory ? (
        <>
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
                      <p className="text-sm text-on-surface-variant">Port risk level</p>
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
                      <p className="text-sm text-on-surface-variant">Port risk level</p>
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
            <>
              <IPReputationCard reputation={result.ip_reputation ?? null} titleEyebrow="IP reputation — independent from port risk" />
              <ThreatAssessmentCard assessment={result.threat_assessment ?? null} titleEyebrow="Overall threat — derived from port risk + IP reputation" />
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
            </>
          )}
        </>
      ) : (
        <>
          <Card className="p-5">
            <div className="flex items-center justify-between gap-4">
              <p className="font-display text-lg font-semibold flex items-center gap-2"><History size={18} className="text-primary" /> Scan history</p>
              <Button variant="secondary" disabled={historyLoading} onClick={() => fetchHistory(historyPage)}>
                {historyLoading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
                Refresh
              </Button>
            </div>
            <p className="mt-2 text-sm text-on-surface-variant">Your previous port scans, newest first. Select a scan to view full details.</p>

            {historyLoading && !history ? (
              <>
                {historySlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={historyElapsed} /></div>}
                <div className="mt-6 space-y-3">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="animate-pulse rounded border bg-surface-low p-4">
                      <div className="h-4 w-1/3 rounded bg-surface-bright/30" />
                      <div className="mt-3 h-3 w-full rounded bg-surface-bright/20" />
                    </div>
                  ))}
                </div>
              </>
            ) : historyError ? (
              <div className="mt-6 rounded border border-destructive/20 bg-destructive/10 p-4">
                <div className="flex items-start gap-3">
                  <AlertCircle size={18} className="mt-0.5 shrink-0 text-destructive" />
                  <div>
                    <p className="font-medium text-destructive">Unable to load history</p>
                    <p className="mt-1 text-sm text-on-surface-variant">{historyError}</p>
                  </div>
                </div>
                <Button className="mt-4" onClick={() => fetchHistory(historyPage)}>Retry</Button>
              </div>
            ) : history && history.length === 0 ? (
              <div className="mt-6 flex flex-col items-center justify-center rounded border bg-surface-low p-10 text-center">
                <span className="mb-4 grid h-14 w-14 place-items-center rounded-full bg-primary/10 text-primary">
                  <Search size={26} />
                </span>
                <h2 className="font-display text-lg font-semibold">No port scans yet</h2>
                <p className="mt-2 max-w-sm text-sm leading-6 text-on-surface-variant">
                  Completed scans will appear here. Run your first port scan to start building history.
                </p>
                <Button className="mt-5" onClick={handleToggleHistory}>
                  <Target size={16} /> Run a new scan
                </Button>
              </div>
            ) : history && history.length > 0 ? (
              <>
                {historyLoading && historySlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={historyElapsed} /></div>}
                {historyLoading && !historySlow && (
                  <div className="mt-4 flex items-center gap-2 text-sm text-on-surface-variant">
                    <Loader2 size={14} className="animate-spin" /> Loading history…
                  </div>
                )}
                <div className="mt-6 overflow-x-auto rounded border">
                  <table className="w-full min-w-[720px] text-left text-sm">
                    <thead className="border-b bg-surface-low font-mono text-[11px] uppercase tracking-wider text-on-surface-variant">
                      <tr>
                        <th className="px-4 py-3 font-medium">Target</th>
                        <th className="px-4 py-3 font-medium">Resolved IP</th>
                        <th className="px-4 py-3 font-medium">Date</th>
                        <th className="px-4 py-3 font-medium">Ports</th>
                        <th className="px-4 py-3 font-medium">Open</th>
                        <th className="px-4 py-3 font-medium">Risk</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                        <th className="px-4 py-3 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((item) => (
                        <tr key={item.id} className="border-b last:border-0 hover:bg-surface-high/40">
                          <td className="px-4 py-3 font-mono font-medium text-on-surface">{item.target}</td>
                          <td className="px-4 py-3 font-mono text-on-surface-variant">{item.resolved_ip ?? '—'}</td>
                          <td className="px-4 py-3 text-on-surface-variant">{formatDate(item.created_at)}</td>
                          <td className="px-4 py-3 font-mono text-on-surface-variant">{item.ports_scanned}</td>
                          <td className="px-4 py-3 font-mono text-on-surface-variant">{item.open_port_count}</td>
                          <td className="px-4 py-3">{getHistoryRiskBadge(item.risk_level)}</td>
                          <td className="px-4 py-3">{getStatusBadge(item.status)}</td>
                          <td className="px-4 py-3">
                            <Button variant="secondary" className="h-8 px-3 text-xs" onClick={() => handleViewDetail(item.id)}>
                              <Eye size={14} /> View
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {historyMeta && historyMeta.total > historyMeta.limit && (
                  <div className="mt-4 flex items-center justify-between gap-3">
                    <p className="text-xs text-on-surface-variant">
                      Page {historyMeta.page} of {totalPages} · {historyMeta.total} scans total
                    </p>
                    <div className="flex gap-2">
                      <Button
                        variant="secondary"
                        disabled={historyLoading || historyPage <= 1}
                        onClick={() => fetchHistory(historyPage - 1)}
                      >
                        <ChevronLeft size={16} /> Previous
                      </Button>
                      <Button
                        variant="secondary"
                        disabled={historyLoading || historyPage >= totalPages}
                        onClick={() => fetchHistory(historyPage + 1)}
                      >
                        Next <ChevronRight size={16} />
                      </Button>
                    </div>
                  </div>
                )}
              </>
            ) : null}
          </Card>

          {detailLoading && (
            <Card className="mt-5 p-5">
              <div className="flex items-center gap-2 text-sm text-on-surface-variant">
                <Loader2 size={16} className="animate-spin" /> Loading scan detail…
              </div>
              {detailSlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={detailElapsed} /></div>}
            </Card>
          )}

          {detailError && (
            <Card className="mt-5 p-5">
              <div className="flex items-start gap-3 rounded border border-destructive/20 bg-destructive/10 p-4">
                <AlertCircle size={18} className="mt-0.5 shrink-0 text-destructive" />
                <div>
                  <p className="font-medium text-destructive">Unable to load scan detail</p>
                  <p className="mt-1 text-sm text-on-surface-variant">{detailError}</p>
                </div>
              </div>
              <Button variant="secondary" className="mt-4" onClick={() => detail && detail.id && handleViewDetail(detail.id)}>Retry</Button>
            </Card>
          )}

          {detail && (
            <>
              <Card className="mt-5 p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm text-on-surface-variant">Port risk level</p>
                    <div className="mt-3 flex items-baseline gap-4">
                      <p className="font-display text-4xl font-bold">{detail.risk_level.toUpperCase()}</p>
                      {getRiskBadge(detail.risk_level)}
                    </div>
                    <p className="mt-2 text-sm text-on-surface-variant">
                      Historical scan · {formatDate(detail.created_at)}
                    </p>
                  </div>
                  <Button variant="secondary" onClick={() => setDetail(null)}>
                    <ArrowLeft size={16} /> Close
                  </Button>
                </div>

                <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  <div className="rounded border bg-surface-low p-4">
                    <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Target size={14} /> Target</p>
                    <p className="mt-2 font-mono text-sm font-semibold text-on-surface">{detail.target}</p>
                  </div>
                  <div className="rounded border bg-surface-low p-4">
                    <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><HardDrive size={14} /> Resolved IP</p>
                    <p className="mt-2 font-mono text-sm font-semibold text-on-surface">{detail.resolved_ip ?? '—'}</p>
                  </div>
                  <div className="rounded border bg-surface-low p-4">
                    <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Clock size={14} /> Duration</p>
                    <p className="mt-2 font-mono text-sm font-semibold text-on-surface">{detail.scan_duration_ms ?? '—'}ms</p>
                  </div>
                  <div className="rounded border bg-surface-low p-4">
                    <p className="text-xs font-medium uppercase tracking-wide text-on-surface-variant">Scanned</p>
                    <p className="mt-2 font-mono text-sm font-semibold text-on-surface">{detail.ports_scanned} ports</p>
                  </div>
                </div>

                <div className="mt-4 flex flex-wrap gap-2 text-sm">
                  <span className="rounded bg-surface-low px-3 py-1 font-mono">Open: {detail.open_port_count}</span>
                  <span className="rounded bg-surface-low px-3 py-1 font-mono">Closed: {detail.closed_port_count}</span>
                  <span className="rounded bg-surface-low px-3 py-1 font-mono">Filtered: {detail.filtered_port_count}</span>
                  <span className="rounded bg-surface-low px-3 py-1 font-mono capitalize">Status: {detail.status}</span>
                </div>
              </Card>

              <div className="mt-5">
                <IPReputationCard reputation={detail.ip_reputation ?? null} titleEyebrow="Historical IP reputation" />
              </div>

              <div className="mt-5">
                <ThreatAssessmentCard assessment={detail.threat_assessment ?? null} titleEyebrow="Historical overall threat" />
              </div>

              <Card className="mt-5">
                <div className="border-b px-5 py-4">
                  <p className="font-display font-semibold flex items-center gap-2">
                    <Layers size={18} className="text-primary" /> Port findings · {detail.open_ports.length} ports
                  </p>
                </div>
                <div className="p-4">
                  {detail.open_ports.length > 0 ? (
                    <DataTable
                      headers={['Port', 'Service', 'State', 'Banner']}
                      rows={detail.open_ports.map((p) => [
                        String(p.port),
                        p.service,
                        p.state,
                        formatBanner(p.banner),
                      ])}
                    />
                  ) : (
                    <div className="py-8 text-center">
                      <p className="text-sm text-on-surface-variant">No port data available.</p>
                    </div>
                  )}
                </div>
              </Card>
            </>
          )}
        </>
      )}
    </>
  );
}
