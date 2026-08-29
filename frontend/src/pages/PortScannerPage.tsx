import { useState, FormEvent, useCallback } from 'react';
import {BookOpen, ArrowRight, Play, Loader2, AlertCircle, Shield, Layers, Clock, Target, HardDrive, ArrowLeft, ChevronLeft, ChevronRight, Eye, History, Globe, Building, Flag, AlertTriangle, CheckCircle, HelpCircle, Activity, Zap, ShieldAlert, ShieldCheck, Radio} from 'lucide-react';
import { Link } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card, DataTable } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import { useSlowRequest } from '../hooks/useSlowRequest';
import { SlowRequestNotice } from '../components/SlowRequestNotice';
import type { PortScanResult, PortScanRequest, PortScanHistoryItem, PortScanDetail, IPReputationResult, ThreatAssessment, ProviderEvidence, ThreatIntelligenceBundle } from '../types';

type ScanMode = 'quick' | 'common' | 'custom';

const PROFILE_LABELS: Record<ScanMode, { title: string; line1: string; line2: string; aria: string }> = {
  quick: { title: 'Quick', line1: '20 common ports', line2: 'Fast', aria: 'Quick — 20 most common ports' },
  common: { title: 'Standard', line1: 'Balanced coverage', line2: 'Up to 100 ports', aria: 'Standard — balanced coverage, up to 100 ports' },
  custom: { title: 'Custom', line1: 'Choose ports', line2: 'Up to 100', aria: 'Custom — choose up to 100 ports' },
};

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
  return <Badge tone={c.tone}><Icon size={12} className="mr-1" aria-hidden="true" />{c.label}</Badge>;
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
  return <Badge tone={tones[level]}><Icon size={12} className="mr-1" aria-hidden="true" />{level.toUpperCase()}</Badge>;
}

function ThreatConfidenceBadge({ confidence }: { confidence: ThreatAssessment['confidence'] }) {
  const tones: Record<ThreatAssessment['confidence'], 'success' | 'primary' | 'warning' | 'danger'> = {
    high: 'success',
    medium: 'warning',
    low: 'danger',
  };
  return <Badge tone={tones[confidence] ?? 'primary'}>{confidence}</Badge>;
}

function PortRiskBadge({ risk }: { risk: PortScanResult['risk_level'] }) {
  const tones: Record<PortScanResult['risk_level'], 'success' | 'primary' | 'warning' | 'danger'> = {
    low: 'success',
    medium: 'warning',
    high: 'danger',
    critical: 'danger',
  };
  const labels: Record<PortScanResult['risk_level'], string> = {
    low: 'LOW',
    medium: 'MEDIUM',
    high: 'HIGH',
    critical: 'CRITICAL',
  };
  const icons: Record<string, typeof Shield> = { low: ShieldCheck, medium: Shield, high: ShieldAlert, critical: Zap };
  const Icon = icons[risk] ?? Shield;
  return <Badge tone={tones[risk]}><Icon size={12} className="mr-1" aria-hidden="true" />{labels[risk]}</Badge>;
}

// Compact scanning state — truthful, no fake percentages
function ScanningState({ elapsedSeconds, isSlow }: { elapsedSeconds: number; isSlow: boolean }) {
  const stages = ['Preparing','Resolving','Checking exposure','Analyzing reputation','Collecting intelligence','Building assessment'];
  return (
    <Card className="p-4" aria-live="polite" aria-busy="true">
      <div className="flex items-start gap-3">
        <span className="grid h-9 w-9 place-items-center rounded-full bg-primary/10 text-primary shrink-0">
          <Loader2 size={16} className="animate-spin" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-display text-sm font-semibold">Scanning…</p>
          <p className="mt-1 text-xs leading-5 text-on-surface-variant">Running security scan — up to 30 seconds. Don’t close this page.</p>
          <div className="mt-3">
            <div className="indeterminate-track w-full max-w-[260px]" aria-hidden="true" />
          </div>
        </div>
      </div>
      <div className="mt-4">
        <p className="eyebrow mb-2 text-[11px]">Steps</p>
        <div className="flex flex-wrap gap-1.5">
          {stages.map((s) => (
            <span key={s} className="inline-flex items-center gap-1.5 rounded-full border bg-surface-low px-2.5 py-1 text-xs text-on-surface-variant">
              <span className="h-1.5 w-1.5 rounded-full bg-primary/60" aria-hidden="true" /> {s}
            </span>
          ))}
        </div>
        <p className="mt-2 text-[11px] leading-4 text-on-surface-variant/70">Backend does not expose per-stage progress — nothing is marked complete until the response arrives.</p>
      </div>
      {isSlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={elapsedSeconds} /></div>}
    </Card>
  );
}

function OverallThreatCard({ assessment }: { assessment: ThreatAssessment | null | undefined }) {
  if (!assessment) {
    return (
      <Card className="p-4 sm:p-5 border-amber-500/20">
        <p className="eyebrow mb-2 flex items-center gap-2"><Shield size={12} aria-hidden="true" /> Overall threat</p>
        <div className="flex items-start gap-3 rounded border bg-surface-low p-3">
          <HelpCircle size={16} className="mt-0.5 text-on-surface-variant shrink-0" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-on-surface">Threat assessment not available.</p>
            <p className="mt-1 text-xs leading-5 text-on-surface-variant">Created before assessment was enabled or could not be built.</p>
          </div>
        </div>
      </Card>
    );
  }
  const scoreTone = assessment.level === 'low' ? 'text-success' : assessment.level === 'critical' ? 'text-danger' : assessment.level === 'high' ? 'text-danger' : 'text-warning';
  return (
    <Card className="p-4 sm:p-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
          <p className="eyebrow mb-2 flex items-center gap-2"><Shield size={12} aria-hidden="true" /> Overall threat</p>
          <div className="flex flex-wrap items-center gap-2">
            <p className={`font-display text-2xl font-bold ${scoreTone}`} aria-label={`Overall threat score ${assessment.score} out of 100, ${assessment.level}`}>{assessment.score} <span className="text-sm font-medium text-on-surface-variant">/ 100</span></p>
            <ThreatLevelBadge level={assessment.level} />
            <span className="inline-flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide text-on-surface-variant">
              <Activity size={11} aria-hidden="true" /> {assessment.confidence}
            </span>
          </div>
          <p className="mt-2 text-sm leading-5 text-on-surface-variant line-clamp-3">{assessment.explanation}</p>
          <p className="mt-1.5 text-[11px] font-mono text-on-surface-variant/70">Assessed {formatDate(assessment.assessed_at)} · {assessment.factors.length} factor(s)</p>
        </div>
        <div className="shrink-0 self-start">
          <ThreatConfidenceBadge confidence={assessment.confidence} />
        </div>
      </div>
      {assessment.factors.length > 0 && (
        <div className="mt-4">
          <p className="eyebrow mb-2 text-[11px]">Factors</p>
          <ul className="space-y-1.5" role="list">
            {assessment.factors.map((f, idx) => (
              <li key={`${f.type}-${idx}`} className="flex items-center justify-between gap-3 rounded border bg-surface-low px-3 py-2">
                <div className="min-w-0">
                  <p className="text-xs font-medium capitalize truncate">{f.type.replace(/_/g, ' ')}</p>
                  <p className="text-[11px] leading-4 text-on-surface-variant truncate">{f.description}</p>
                </div>
                <Badge tone={f.weight > 0 ? 'warning' : 'primary'}>+{f.weight}</Badge>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

function PortRiskCard({ result }: { result: PortScanResult | PortScanDetail }) {
  const risk = result.risk_level;
  return (
    <Card className="p-4 sm:p-5">
      <p className="eyebrow mb-2 flex items-center gap-2"><ShieldAlert size={12} aria-hidden="true" /> Port risk</p>
      <div className="flex flex-wrap items-center gap-2">
        <p className="font-display text-xl font-bold">{risk.toUpperCase()}</p>
        <PortRiskBadge risk={risk} />
      </div>
      <p className="mt-1.5 text-xs leading-5 text-on-surface-variant">{(result as PortScanResult).summary ?? `Scanned ${result.ports_scanned} ports`}</p>
      <div className="mt-3 flex flex-wrap gap-1.5 text-xs font-mono">
        <span className="rounded bg-surface-low px-2 py-1 border">Open: {(result as PortScanResult).open_ports?.filter(p=>p.state==='open').length ?? (result as PortScanDetail).open_port_count ?? 0}</span>
        <span className="rounded bg-surface-low px-2 py-1 border">Scanned: {result.ports_scanned}</span>
        <span className="rounded bg-surface-low px-2 py-1 border truncate max-w-[180px]">Target: {result.target}</span>
        {result.resolved_ip && <span className="rounded bg-surface-low px-2 py-1 border">IP: {result.resolved_ip}</span>}
      </div>
    </Card>
  );
}

function IPReputationCard({ reputation, titleEyebrow }: { reputation: IPReputationResult | null | undefined; titleEyebrow?: string }) {
  if (!reputation) {
    return (
      <Card className="p-4 sm:p-5">
        <p className="eyebrow mb-1">{titleEyebrow ?? 'IP reputation'}</p>
        <div className="flex items-start gap-2 rounded border bg-surface-low p-3 mt-3">
          <HelpCircle size={16} className="mt-0.5 text-on-surface-variant shrink-0" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-on-surface">No IP reputation data.</p>
            <p className="mt-1 text-xs leading-5 text-on-surface-variant">UNKNOWN ≠ CLEAN · UNAVAILABLE ≠ CLEAN</p>
          </div>
        </div>
      </Card>
    );
  }

  const isUnavailable = reputation.reputation === 'unavailable';
  const isUnknown = reputation.reputation === 'unknown';

  return (
    <Card className="p-4 sm:p-5">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="eyebrow mb-2">{titleEyebrow ?? 'IP reputation'}</p>
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-display text-xl font-bold">{reputation.reputation.toUpperCase()}</p>
            <ReputationBadge reputation={reputation.reputation} />
            {!isUnavailable && !isUnknown && <ConfidenceBadge confidence={reputation.confidence} />}
          </div>
          <p className="mt-1.5 text-xs leading-5 text-on-surface-variant">
            {isUnavailable && 'Provider unavailable or IP not checked. UNAVAILABLE ≠ CLEAN.'}
            {isUnknown && 'No reputation data reported. UNKNOWN ≠ CLEAN.'}
            {reputation.reputation === 'clean' && 'No abuse reported.'}
            {reputation.reputation === 'suspicious' && `${reputation.reports} report${reputation.reports === 1 ? '' : 's'} · suspicious.`}
            {reputation.reputation === 'malicious' && `${reputation.reports} report${reputation.reports === 1 ? '' : 's'} · malicious.`}
          </p>
        </div>
        <Badge tone="primary"><Globe size={12} className="mr-1" aria-hidden="true" />{reputation.provider}</Badge>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded border bg-surface-low p-3 min-w-0">
          <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-on-surface-variant"><Globe size={12} aria-hidden="true" /> IP</p>
          <p className="mt-1.5 font-mono text-xs font-semibold text-on-surface break-all">{reputation.ip}</p>
          <p className="mt-1 text-[11px] text-on-surface-variant">Reports: {reputation.reports}</p>
        </div>
        <div className="rounded border bg-surface-low p-3">
          <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-on-surface-variant"><Flag size={12} aria-hidden="true" /> Country / ASN</p>
          <p className="mt-1.5 font-mono text-xs font-semibold text-on-surface">{reputation.country ?? '—'} {reputation.asn ? `· AS${reputation.asn}` : ''}</p>
          <p className="mt-1 text-[11px] text-on-surface-variant">ASN: {reputation.asn ?? '—'}</p>
        </div>
        <div className="rounded border bg-surface-low p-3 min-w-0">
          <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-on-surface-variant"><Building size={12} aria-hidden="true" /> Organization</p>
          <p className="mt-1.5 text-xs font-semibold text-on-surface break-words leading-4">{reputation.organization ?? reputation.isp ?? '—'}</p>
          <p className="mt-1 text-[11px] text-on-surface-variant break-words">{reputation.isp ?? ''}</p>
        </div>
        <div className="rounded border bg-surface-low p-3">
          <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-on-surface-variant"><Clock size={12} aria-hidden="true" /> Last reported</p>
          <p className="mt-1.5 text-xs font-semibold text-on-surface">{reputation.last_reported_at ? formatDate(reputation.last_reported_at) : '—'}</p>
          <p className="mt-1 text-[11px] text-on-surface-variant">Checked: {reputation.checked_at ? formatDate(reputation.checked_at) : '—'}</p>
        </div>
      </div>

      {reputation.reason && isUnavailable && (
        <p className="mt-3 text-[11px] font-mono text-on-surface-variant/70 break-words">Reason: {reputation.reason}</p>
      )}
    </Card>
  );
}

function ThreatIntelligenceCard({ bundle, titleEyebrow }: { bundle: ThreatIntelligenceBundle | null | undefined; titleEyebrow?: string }) {
  if (!bundle || !bundle.providers || bundle.providers.length === 0) {
    return (
      <Card className="p-4 sm:p-5">
        <p className="eyebrow mb-1">{titleEyebrow ?? 'Threat intelligence'}</p>
        <div className="flex items-start gap-2 rounded border bg-surface-low p-3 mt-3">
          <HelpCircle size={16} className="mt-0.5 text-on-surface-variant shrink-0" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-on-surface">Threat intelligence unavailable</p>
            <p className="mt-1 text-xs leading-5 text-on-surface-variant">This scan does not contain threat intelligence data.</p>
          </div>
        </div>
      </Card>
    );
  }
  const overall = bundle.summary?.overall_reputation ?? 'unknown';
  const isMixed = bundle.providers.length > 1;
  return (
    <Card className="p-4 sm:p-5">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="eyebrow mb-2">{titleEyebrow ?? 'Threat intelligence'}</p>
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-display text-xl font-bold">{overall.toUpperCase()}</p>
            <ReputationBadge reputation={overall as IPReputationResult['reputation']} />
            <Badge tone="primary"><Activity size={12} className="mr-1" aria-hidden="true" />{bundle.sources_available}/{bundle.sources_checked}</Badge>
          </div>
          <p className="mt-1.5 text-xs text-on-surface-variant">
            Overall {overall} · {bundle.summary?.evidence_confidence ?? bundle.confidence} confidence · {bundle.checked_at ? formatDate(bundle.checked_at) : '—'} {isMixed ? '· multi-provider' : ''}
          </p>
          <p className="mt-1 text-[11px] text-on-surface-variant/70">UNKNOWN ≠ CLEAN · UNAVAILABLE ≠ CLEAN</p>
        </div>
      </div>

      <div className="mt-4 space-y-2">
        {bundle.providers.map((p: ProviderEvidence) => (
          <div key={p.provider} className="rounded border bg-surface-low p-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <p className="text-[11px] font-medium uppercase tracking-wide text-on-surface-variant flex items-center gap-1.5"><Radio size={12} aria-hidden="true" /> {p.provider}</p>
              <div className="flex items-center gap-1.5 flex-wrap">
                <ReputationBadge reputation={p.reputation} />
                {p.confidence && p.confidence !== 'none' && <ConfidenceBadge confidence={p.confidence} />}
                <Badge tone={p.status === 'available' ? 'success' : p.status === 'unknown' ? 'primary' : 'warning'}>{p.status}</Badge>
              </div>
            </div>
            <div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-4 text-xs">
              <div>
                <p className="text-[11px] uppercase tracking-wide text-on-surface-variant">Reputation</p>
                <p className="font-mono font-semibold capitalize">{p.reputation}</p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wide text-on-surface-variant">Confidence</p>
                <p className="font-mono font-semibold">{p.confidence ?? '—'}</p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wide text-on-surface-variant">Threat score</p>
                <p className="font-mono font-semibold">{String(p.threat_score ?? (p.evidence as Record<string, unknown> | null)?.threat_score ?? '—')}</p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wide text-on-surface-variant">Last seen</p>
                <p className="font-mono font-semibold">{p.last_seen ? formatDate(p.last_seen) : `${String(p.days_since_activity ?? (p.evidence as Record<string, unknown> | null)?.days_since_activity ?? '—')} days`}</p>
              </div>
            </div>
            {(p.visitor_type !== null && p.visitor_type !== undefined) || (p.visitor_type_name) ? (
              <div className="mt-2 text-xs">
                <p className="text-[11px] uppercase tracking-wide text-on-surface-variant">Visitor type</p>
                <p className="font-mono break-words text-xs">{p.visitor_type_name ?? p.visitor_type} {p.categories && p.categories.length ? `· ${p.categories.join(', ')}` : ''}</p>
              </div>
            ) : null}
            {p.reason && (
              <p className="mt-1.5 text-[11px] font-mono text-on-surface-variant/70 break-words">Reason: {p.reason}</p>
            )}
            <p className="mt-1 text-[11px] font-mono text-on-surface-variant/60">Checked: {p.checked_at ? formatDate(p.checked_at) : '—'}</p>
          </div>
        ))}
      </div>
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

  const [showHistory, setShowHistory] = useState(false);
  const [history, setHistory] = useState<PortScanHistoryItem[] | null>(null);
  const [historyMeta, setHistoryMeta] = useState<{ total: number; page: number; limit: number } | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyPage, setHistoryPage] = useState(1);
  const historyLimit = 20;
  const { run: runHistory, isSlow: historySlow, elapsedSeconds: historyElapsed } = useSlowRequest();

  const [detail, setDetail] = useState<PortScanDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const { run: runDetail, isSlow: detailSlow, elapsedSeconds: detailElapsed } = useSlowRequest();

  const mapError = (err: unknown, fallback: string): string => {
    if (err instanceof ApiClientError) {
      if (err.status === 401) return 'Your session has expired. Please sign in again.';
      if (err.status === 400) return err.message || 'Invalid target. Enter a public domain or IP address.';
      if (err.status === 429) return err.message || 'Rate limit reached. Too many scans — please wait a few minutes and try again.';
      if (err.status === 503) return 'Security scan is temporarily unavailable. Please try again later.';
      if (err.status === 0) return 'Unable to connect to the backend. Check your connection and try again.';
      return err.message || fallback;
    }
    return fallback;
  };

  const handleScan = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const trimmed = target.trim();
    if (!trimmed) {
      setError('Enter a domain or public IP address to scan.');
      return;
    }
    if (trimmed.includes('://')) {
      setError('Enter a hostname or IP without scheme (e.g., example.com, not https://example.com).');
      return;
    }
    if (trimmed.includes('@')) {
      setError('Target must not contain credentials.');
      return;
    }

    setIsScanning(true);
    setError(null);
    setResult(null);

    let requestBody: PortScanRequest = { target: trimmed };

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
      if (ports.length > 100) {
        setError('Too many ports — maximum is 100 per scan.');
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
      setError(mapError(err, 'Scan failed. Please try again.'));
    } finally {
      setIsScanning(false);
    }
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

  const getHistoryErrorMessage = (err: unknown, fallback: string): string => mapError(err, fallback);

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
        else if (err.status === 429) setDetailError('Rate limit reached. Please wait and try again.');
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
    <div className="mx-auto w-full max-w-[960px] overflow-hidden">
      <PageHeader
        eyebrow="Security operations"
        title="Security Scan"
        description="Scan a public target for open ports and available threat intelligence."
        actions={
          <Button variant="secondary" onClick={handleToggleHistory} disabled={isScanning && !showHistory} aria-label={showHistory ? 'Back to security scan' : 'View scan history'}>
            {showHistory ? <ArrowLeft size={16} aria-hidden="true" /> : <History size={16} aria-hidden="true" />}
            {showHistory ? 'Back to scan' : 'History'}
          </Button>
        }
      />

      {!showHistory ? (
        <>
          {/* ── compact form card ── */}
          <Card className="p-4 sm:p-5 overflow-hidden">
            <p className="eyebrow">Security scan</p>
            <form onSubmit={handleScan} className="mt-4 grid gap-4" noValidate>
              <div className="grid gap-1.5 min-w-0">
                <label htmlFor="scan-target" className="text-sm font-medium text-on-surface">Target</label>
                <input
                  id="scan-target"
                  type="text"
                  placeholder="example.com / 1.1.1.1"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={isScanning}
                  required
                  aria-required="true"
                  aria-describedby="target-help"
                  autoComplete="off"
                  className="h-11 w-full min-w-0 rounded border bg-surface-low px-3 placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 disabled:opacity-60"
                />
                <p id="target-help" className="text-xs leading-5 text-on-surface-variant">
                  Public targets only · private/local targets are blocked.
                </p>
              </div>

              <fieldset className="grid gap-2 min-w-0" disabled={isScanning} aria-describedby="profile-help">
                <legend className="text-sm font-medium text-on-surface">Scan profile</legend>
                <div className="grid gap-2 grid-cols-1 sm:grid-cols-3">
                  {(Object.keys(PROFILE_LABELS) as ScanMode[]).map((mode) => (
                    <button
                      key={mode}
                      type="button"
                      onClick={() => setScanMode(mode)}
                      disabled={isScanning}
                      aria-pressed={scanMode === mode}
                      aria-label={PROFILE_LABELS[mode].aria}
                      className={`rounded border px-3 py-3 text-left transition focus:outline-none focus:ring-2 focus:ring-primary/60 min-w-0 ${
                        scanMode === mode
                          ? 'border-primary/40 bg-primary/10 text-primary'
                          : 'border-outline-variant/70 bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface'
                      }`}
                    >
                      <p className="text-sm font-semibold truncate">{PROFILE_LABELS[mode].title}</p>
                      <p className="mt-0.5 text-xs leading-4 text-on-surface-variant truncate">{PROFILE_LABELS[mode].line1}</p>
                      <p className="text-[11px] leading-4 text-on-surface-variant/70">{PROFILE_LABELS[mode].line2}</p>
                    </button>
                  ))}
                </div>
                <p id="profile-help" className="sr-only">Quick 20 ports, Standard up to 100, Custom up to 100.</p>
              </fieldset>

              {scanMode === 'custom' && (
                <div className="grid gap-1.5 min-w-0">
                  <label htmlFor="custom-ports" className="text-sm font-medium text-on-surface">Ports</label>
                  <textarea
                    id="custom-ports"
                    rows={2}
                    placeholder="22, 80, 443"
                    value={customPorts}
                    onChange={(e) => setCustomPorts(e.target.value)}
                    disabled={isScanning}
                    aria-describedby="custom-ports-help"
                    className="w-full min-w-0 rounded border bg-surface-low p-3 font-mono text-sm text-on-surface placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 resize-none disabled:opacity-60"
                  />
                  <p id="custom-ports-help" className="text-xs leading-5 text-on-surface-variant">
                    Enter up to 100 ports separated by commas.
                  </p>
                </div>
              )}

              <Button type="submit" disabled={isScanning || !target.trim()} className="w-full" aria-label="Start security scan">
                {isScanning ? (
                  <> <Loader2 size={16} className="animate-spin mr-2" aria-hidden="true" /> Scanning… </>
                ) : (
                  <> <Play size={16} className="mr-2" aria-hidden="true" /> Start Security Scan </>
                )}
              </Button>

              {error && (
                <div role="alert" className="flex items-start gap-2 rounded border border-destructive/20 bg-destructive/10 p-3 text-sm text-destructive break-words">
                  <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true" /> <span className="min-w-0">{error}</span>
                </div>
              )}

              <div className="flex items-start gap-2 rounded border bg-surface-low px-3 py-2.5">
                <BookOpen size={14} className="mt-0.5 shrink-0 text-primary" aria-hidden="true" />
                <p className="text-xs leading-5 text-on-surface-variant min-w-0">
                  New to port scanning?{' '}
                  <Link to="/tutorials/port-scanner/what-is-a-port" className="font-semibold text-primary hover:underline focus:outline-none focus:ring-2 focus:ring-primary/60 rounded">
                    Learn what ports are and how to read your scan <ArrowRight size={12} className="inline" aria-hidden="true" />
                  </Link>
                </p>
              </div>
            </form>
          </Card>

          {/* ── loading ── */}
          {isScanning && (
            <div className="mt-5">
              <ScanningState elapsedSeconds={elapsedSeconds} isSlow={isSlow} />
            </div>
          )}

          {/* ── results hierarchy (A-E) ── */}
          {!isScanning && result ? (
            <div className="mt-6">
              <p className="eyebrow mb-3">Results</p>
              <div className="grid gap-4">
                <OverallThreatCard assessment={result.threat_assessment ?? null} />
                <PortRiskCard result={result} />
                <IPReputationCard reputation={result.ip_reputation ?? null} />
                <ThreatIntelligenceCard bundle={result.threat_intelligence ?? null} />
                <Card className="overflow-hidden">
                  <div className="border-b px-4 sm:px-5 py-3 flex items-center justify-between gap-3 flex-wrap">
                    <p className="font-display text-sm font-semibold flex items-center gap-2 min-w-0">
                      <Layers size={16} className="text-primary shrink-0" aria-hidden="true" /> <span className="truncate">Technical port details</span>
                    </p>
                    <span className="text-xs font-mono text-on-surface-variant shrink-0">{result.open_ports.length} open · {result.closed_ports} closed · {result.filtered_ports} filtered</span>
                  </div>
                  <div className="p-3 sm:p-4 overflow-hidden">
                    {result.open_ports.length > 0 ? (
                      <div className="overflow-x-auto -mx-3 sm:mx-0">
                        <div className="px-3 sm:px-0 min-w-[520px]">
                          <DataTable
                            headers={['Port', 'Service', 'State', 'Banner']}
                            rows={result.open_ports.map((p) => [
                              String(p.port),
                              p.service,
                              p.state,
                              formatBanner(p.banner),
                            ])}
                          />
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <p className="text-sm text-on-surface-variant">No open ports found.</p>
                        <p className="mt-1 text-xs text-on-surface-variant/70">All scanned ports were closed or filtered.</p>
                      </div>
                    )}
                  </div>
                </Card>
              </div>
            </div>
          ) : null}
        </>
      ) : (
        <>
          <Card className="p-4 sm:p-5 overflow-hidden">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <p className="font-display text-base font-semibold flex items-center gap-2"><History size={16} className="text-primary" aria-hidden="true" /> Scan history</p>
              <Button variant="secondary" disabled={historyLoading} onClick={() => fetchHistory(historyPage)} aria-label="Refresh scan history">
                {historyLoading ? <Loader2 size={16} className="animate-spin" aria-hidden="true" /> : <History size={16} aria-hidden="true" />}
                Refresh
              </Button>
            </div>
            <p className="mt-1.5 text-xs leading-5 text-on-surface-variant">Previous scans, newest first. Select a scan to view full details.</p>

            {historyLoading && !history ? (
              <>
                {historySlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={historyElapsed} /></div>}
                <div className="mt-6 space-y-3" aria-hidden="true">
                  {Array.from({ length: 3 }).map((_, i) => (
                    <div key={i} className="animate-pulse rounded border bg-surface-low p-4">
                      <div className="h-4 w-1/3 rounded bg-surface-bright/30" />
                      <div className="mt-3 h-3 w-full rounded bg-surface-bright/20" />
                    </div>
                  ))}
                </div>
              </>
            ) : historyError ? (
              <div className="mt-6 rounded border border-destructive/20 bg-destructive/10 p-4" role="alert">
                <div className="flex items-start gap-3">
                  <AlertCircle size={18} className="mt-0.5 shrink-0 text-destructive" aria-hidden="true" />
                  <div className="min-w-0">
                    <p className="font-medium text-destructive">Unable to load history</p>
                    <p className="mt-1 text-sm text-on-surface-variant break-words">{historyError}</p>
                  </div>
                </div>
                <Button className="mt-4" onClick={() => fetchHistory(historyPage)}>Retry</Button>
              </div>
            ) : history && history.length === 0 ? (
              <div className="mt-6 flex flex-col items-center justify-center rounded border bg-surface-low p-8 text-center">
                <span className="mb-3 grid h-12 w-12 place-items-center rounded-full bg-primary/10 text-primary">
                  <History size={22} aria-hidden="true" />
                </span>
                <h2 className="font-display text-base font-semibold">No security scans yet</h2>
                <p className="mt-2 max-w-sm text-sm leading-6 text-on-surface-variant">
                  Completed scans will appear here.
                </p>
                <Button className="mt-4" onClick={handleToggleHistory}>
                  <Target size={16} aria-hidden="true" /> Run a new scan
                </Button>
              </div>
            ) : history && history.length > 0 ? (
              <>
                {historyLoading && historySlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={historyElapsed} /></div>}
                {historyLoading && !historySlow && (
                  <div className="mt-4 flex items-center gap-2 text-sm text-on-surface-variant" role="status" aria-live="polite">
                    <Loader2 size={14} className="animate-spin" aria-hidden="true" /> Loading history…
                  </div>
                )}
                <div className="mt-6 overflow-x-auto rounded border -mx-4 sm:mx-0">
                  <div className="min-w-[720px] px-4 sm:px-0">
                  <table className="w-full text-left text-sm">
                    <thead className="border-b bg-surface-low font-mono text-[11px] uppercase tracking-wider text-on-surface-variant">
                      <tr>
                        <th className="px-4 py-3 font-medium">Target</th>
                        <th className="px-4 py-3 font-medium">Resolved IP</th>
                        <th className="px-4 py-3 font-medium">Date</th>
                        <th className="px-4 py-3 font-medium">Ports</th>
                        <th className="px-4 py-3 font-medium">Open</th>
                        <th className="px-4 py-3 font-medium">Port risk</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                        <th className="px-4 py-3 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((item) => (
                        <tr key={item.id} className="border-b last:border-0 hover:bg-surface-high/40">
                          <td className="px-4 py-3 font-mono font-medium text-on-surface break-all max-w-[180px]">{item.target}</td>
                          <td className="px-4 py-3 font-mono text-on-surface-variant break-all">{item.resolved_ip ?? '—'}</td>
                          <td className="px-4 py-3 text-on-surface-variant whitespace-nowrap">{formatDate(item.created_at)}</td>
                          <td className="px-4 py-3 font-mono text-on-surface-variant">{item.ports_scanned}</td>
                          <td className="px-4 py-3 font-mono text-on-surface-variant">{item.open_port_count}</td>
                          <td className="px-4 py-3">{getHistoryRiskBadge(item.risk_level)}</td>
                          <td className="px-4 py-3">{getStatusBadge(item.status)}</td>
                          <td className="px-4 py-3">
                            <Button variant="secondary" className="h-8 px-3 text-xs" onClick={() => handleViewDetail(item.id)} aria-label={`View scan detail for ${item.target}`}>
                              <Eye size={14} aria-hidden="true" /> View
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  </div>
                </div>

                {historyMeta && historyMeta.total > historyMeta.limit && (
                  <div className="mt-4 flex items-center justify-between gap-3 flex-wrap">
                    <p className="text-xs text-on-surface-variant">
                      Page {historyMeta.page} of {totalPages} · {historyMeta.total} scans total
                    </p>
                    <div className="flex gap-2">
                      <Button
                        variant="secondary"
                        disabled={historyLoading || historyPage <= 1}
                        onClick={() => fetchHistory(historyPage - 1)}
                        aria-label="Previous page"
                      >
                        <ChevronLeft size={16} aria-hidden="true" /> Previous
                      </Button>
                      <Button
                        variant="secondary"
                        disabled={historyLoading || historyPage >= totalPages}
                        onClick={() => fetchHistory(historyPage + 1)}
                        aria-label="Next page"
                      >
                        Next <ChevronRight size={16} aria-hidden="true" />
                      </Button>
                    </div>
                  </div>
                )}
              </>
            ) : null}
          </Card>

          {detailLoading && (
            <Card className="mt-5 p-4 sm:p-5">
              <div className="flex items-center gap-2 text-sm text-on-surface-variant" role="status" aria-live="polite">
                <Loader2 size={16} className="animate-spin" aria-hidden="true" /> Loading scan detail…
              </div>
              {detailSlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={detailElapsed} /></div>}
            </Card>
          )}

          {detailError && (
            <Card className="mt-5 p-4 sm:p-5">
              <div className="flex items-start gap-3 rounded border border-destructive/20 bg-destructive/10 p-4" role="alert">
                <AlertCircle size={18} className="mt-0.5 shrink-0 text-destructive" aria-hidden="true" />
                <div className="min-w-0">
                  <p className="font-medium text-destructive">Unable to load scan detail</p>
                  <p className="mt-1 text-sm text-on-surface-variant break-words">{detailError}</p>
                </div>
              </div>
              <Button variant="secondary" className="mt-4" onClick={() => detail && detail.id && handleViewDetail(detail.id)}>Retry</Button>
            </Card>
          )}

          {detail && (
            <>
              <div className="mt-6 grid gap-4">
                <OverallThreatCard assessment={detail.threat_assessment ?? null} />
                <PortRiskCard result={detail} />
                <IPReputationCard reputation={detail.ip_reputation ?? null} titleEyebrow="IP reputation — historical" />
                <ThreatIntelligenceCard bundle={detail.threat_intelligence ?? null} titleEyebrow="Threat intelligence — historical" />

                <Card className="overflow-hidden">
                  <div className="border-b px-4 sm:px-5 py-3 flex items-center justify-between gap-3 flex-wrap">
                    <p className="font-display text-sm font-semibold flex items-center gap-2">
                      <Layers size={16} className="text-primary" aria-hidden="true" /> Port findings · {detail.open_ports.length} ports
                    </p>
                    <span className="text-xs font-mono text-on-surface-variant">Historical · {formatDate(detail.created_at)}</span>
                  </div>
                  <div className="p-3 sm:p-4 overflow-hidden">
                    <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <div className="rounded border bg-surface-low p-3 min-w-0">
                        <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-on-surface-variant"><Target size={12} aria-hidden="true" /> Target</p>
                        <p className="mt-1 font-mono text-xs font-semibold text-on-surface break-all">{detail.target}</p>
                      </div>
                      <div className="rounded border bg-surface-low p-3 min-w-0">
                        <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-on-surface-variant"><HardDrive size={12} aria-hidden="true" /> Resolved IP</p>
                        <p className="mt-1 font-mono text-xs font-semibold text-on-surface break-all">{detail.resolved_ip ?? '—'}</p>
                      </div>
                      <div className="rounded border bg-surface-low p-3">
                        <p className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-on-surface-variant"><Clock size={12} aria-hidden="true" /> Duration</p>
                        <p className="mt-1 font-mono text-xs font-semibold text-on-surface">{detail.scan_duration_ms ?? '—'}ms</p>
                      </div>
                      <div className="rounded border bg-surface-low p-3">
                        <p className="text-[11px] font-medium uppercase tracking-wide text-on-surface-variant">Scanned</p>
                        <p className="mt-1 font-mono text-xs font-semibold text-on-surface">{detail.ports_scanned} ports</p>
                      </div>
                    </div>
                    <div className="mb-3 flex flex-wrap gap-1.5 text-xs font-mono">
                      <span className="rounded bg-surface-low px-2 py-1 border">Open: {detail.open_port_count}</span>
                      <span className="rounded bg-surface-low px-2 py-1 border">Closed: {detail.closed_port_count}</span>
                      <span className="rounded bg-surface-low px-2 py-1 border">Filtered: {detail.filtered_port_count}</span>
                      <span className="rounded bg-surface-low px-2 py-1 border capitalize">Status: {detail.status}</span>
                    </div>
                    {detail.open_ports.length > 0 ? (
                      <div className="overflow-x-auto -mx-3 sm:mx-0">
                        <div className="px-3 sm:px-0 min-w-[520px]">
                          <DataTable
                            headers={['Port', 'Service', 'State', 'Banner']}
                            rows={detail.open_ports.map((p) => [
                              String(p.port),
                              p.service,
                              p.state,
                              formatBanner(p.banner),
                            ])}
                          />
                        </div>
                      </div>
                    ) : (
                      <div className="py-8 text-center">
                        <p className="text-sm text-on-surface-variant">No port data available.</p>
                      </div>
                    )}
                  </div>
                </Card>
                <div className="flex justify-end">
                  <Button variant="secondary" onClick={() => setDetail(null)} aria-label="Close scan detail"><ArrowLeft size={16} aria-hidden="true" /> Close detail</Button>
                </div>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
