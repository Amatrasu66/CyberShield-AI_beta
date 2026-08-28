import { useState, FormEvent, useCallback } from 'react';
import {BookOpen, ArrowRight, Play, Loader2, AlertCircle, Shield, Search, Layers, Clock, Target, HardDrive, ArrowLeft, ChevronLeft, ChevronRight, Eye, History, Globe, Building, Flag, AlertTriangle, CheckCircle, HelpCircle, Activity, Zap, Info, ShieldAlert, ShieldCheck, Database, Radio} from 'lucide-react';
import { Link } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card, DataTable } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import { useSlowRequest } from '../hooks/useSlowRequest';
import { SlowRequestNotice } from '../components/SlowRequestNotice';
import type { PortScanResult, PortScanRequest, PortScanHistoryItem, PortScanDetail, IPReputationResult, ThreatAssessment, ProviderEvidence, ThreatIntelligenceBundle } from '../types';

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

// Scan profiles are derived from backend validators: QUICK=20 ports, COMMON= up to 100 (clamped from 117)
const PROFILE_META: Record<string, { label: string; short: string; detail: string }> = {
  quick: { label: 'Quick', short: 'Quick — 20 ports', detail: 'Fast scan with limited port coverage. Covers the 20 most commonly exposed services.' },
  common: { label: 'Standard', short: 'Standard — up to 100 ports', detail: 'Balanced coverage for normal assessments. Scans a broader set of common services (backend clamps to 100 ports max).' },
  custom: { label: 'Custom', short: 'Custom', detail: 'Specify up to 100 ports to scan. Duplicates are removed and ports are validated server-side.' },
};

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

// Scanning explanatory sequence — never fakes progress percentage, never marks as completed unless backend returns
function ScanningState({ elapsedSeconds, isSlow }: { elapsedSeconds: number; isSlow: boolean }) {
  const stages = [
    { label: 'Preparing scan', desc: 'Validating target and scan profile' },
    { label: 'Resolving target', desc: 'Resolving domain to public IP (TOCTOU-safe, single lookup)' },
    { label: 'Checking network exposure', desc: 'TCP connect scan with bounded concurrency' },
    { label: 'Analyzing IP reputation', desc: 'Checking available reputation information for the resolved public IP' },
    { label: 'Collecting threat intelligence', desc: 'Collecting evidence from configured intelligence providers' },
    { label: 'Building threat assessment', desc: 'Combining evidence into derived overall threat' },
  ];
  return (
    <Card className="p-5" aria-live="polite" aria-busy="true">
      <div className="flex items-start gap-3">
        <span className="grid h-10 w-10 place-items-center rounded-full bg-primary/10 text-primary shrink-0">
          <Loader2 size={18} className="animate-spin" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-display text-base font-semibold">Analyzing…</p>
          <p className="mt-1 text-sm leading-6 text-on-surface-variant">CyberShield is running your security scan. This may take up to 30 seconds for a full port sweep. Do not close this page.</p>
          <div className="mt-3">
            <div className="indeterminate-track w-full max-w-[260px]" aria-hidden="true" />
          </div>
        </div>
      </div>
      <div className="mt-6">
        <p className="eyebrow mb-3">What is happening</p>
        <ol className="space-y-2">
          {stages.map((s) => (
            <li key={s.label} className="flex items-start gap-3 rounded border bg-surface-low px-3 py-2.5">
              <span className="mt-1.5 h-2 w-2 rounded-full bg-primary/60 shrink-0" aria-hidden="true" />
              <div>
                <p className="text-sm font-medium text-on-surface">{s.label}</p>
                <p className="text-xs leading-5 text-on-surface-variant">{s.desc}</p>
              </div>
            </li>
          ))}
        </ol>
        <p className="mt-3 text-xs leading-5 text-on-surface-variant">These steps are shown for explanation. The backend does not expose per-stage progress, so no stage is marked “completed” until the full response arrives.</p>
      </div>
      {isSlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={elapsedSeconds} /></div>}
    </Card>
  );
}

function OverallThreatCard({ assessment }: { assessment: ThreatAssessment | null | undefined }) {
  if (!assessment) {
    return (
      <Card className="p-5 border-amber-500/20">
        <p className="eyebrow mb-2 flex items-center gap-2"><Shield size={14} aria-hidden="true" /> Overall threat — derived by CyberShield</p>
        <div className="flex items-start gap-3 rounded border bg-surface-low p-4">
          <HelpCircle size={18} className="mt-0.5 text-on-surface-variant shrink-0" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-on-surface">Threat assessment not available for this scan.</p>
            <p className="mt-1 text-sm leading-6 text-on-surface-variant">This scan was created before overall threat assessment was enabled or the assessment could not be built.</p>
          </div>
        </div>
      </Card>
    );
  }
  const scoreTone = assessment.level === 'low' ? 'text-success' : assessment.level === 'critical' ? 'text-danger' : assessment.level === 'high' ? 'text-danger' : 'text-warning';
  return (
    <Card className="p-5 border-primary/20">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <p className="eyebrow mb-2 flex items-center gap-2"><Shield size={14} aria-hidden="true" /> Overall threat</p>
          <p className="text-xs font-mono uppercase tracking-wide text-on-surface-variant">Derived from available port-risk and threat-intelligence evidence</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <p className={`font-display text-3xl font-bold ${scoreTone}`} aria-label={`Overall threat score ${assessment.score} out of 100, ${assessment.level}`}>{assessment.score} <span className="text-lg font-medium text-on-surface-variant">/ 100</span></p>
            <ThreatLevelBadge level={assessment.level} />
            <span className="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wide text-on-surface-variant">
              <Activity size={12} aria-hidden="true" /> {assessment.confidence} confidence
            </span>
          </div>
          <p className="mt-3 text-sm leading-6 text-on-surface-variant">{assessment.explanation}</p>
          <p className="mt-2 text-xs font-mono text-on-surface-variant/70">Assessed: {formatDate(assessment.assessed_at)} · {assessment.factors.length} factor(s)</p>
        </div>
        <div className="flex shrink-0 items-center gap-2 self-start">
          <ThreatConfidenceBadge confidence={assessment.confidence} />
        </div>
      </div>

      {assessment.factors.length > 0 && (
        <div className="mt-6">
          <p className="eyebrow mb-2">Contributing factors</p>
          <ul className="space-y-2" role="list">
            {assessment.factors.map((f, idx) => (
              <li key={`${f.type}-${idx}`} className="flex items-center justify-between gap-3 rounded border bg-surface-low px-3 py-2">
                <div className="min-w-0">
                  <p className="text-sm font-medium capitalize truncate">{f.type.replace(/_/g, ' ')}</p>
                  <p className="text-xs text-on-surface-variant">{f.description}</p>
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
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="eyebrow mb-2 flex items-center gap-2"><ShieldAlert size={14} aria-hidden="true" /> Port risk</p>
          <p className="text-xs font-mono uppercase tracking-wide text-on-surface-variant">Based on open services only — independent from IP reputation</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <p className="font-display text-2xl font-bold">{risk.toUpperCase()}</p>
            <PortRiskBadge risk={risk} />
          </div>
          <p className="mt-2 text-sm text-on-surface-variant">{(result as PortScanResult).summary ?? `Scanned ${result.ports_scanned} ports`}</p>
        </div>
      </div>
      <div className="mt-4 flex flex-wrap gap-2 text-xs font-mono">
        <span className="rounded bg-surface-low px-3 py-1 border">Open: {(result as PortScanResult).open_ports?.filter(p=>p.state==='open').length ?? (result as PortScanDetail).open_port_count ?? 0}</span>
        <span className="rounded bg-surface-low px-3 py-1 border">Scanned: {result.ports_scanned}</span>
        <span className="rounded bg-surface-low px-3 py-1 border">Target: {result.target}</span>
        {result.resolved_ip && <span className="rounded bg-surface-low px-3 py-1 border">IP: {result.resolved_ip}</span>}
      </div>
    </Card>
  );
}

function IPReputationCard({ reputation, titleEyebrow }: { reputation: IPReputationResult | null | undefined; titleEyebrow?: string }) {
  if (!reputation) {
    return (
      <Card className="p-5">
        <p className="eyebrow mb-2">{titleEyebrow ?? 'IP reputation'}</p>
        <p className="text-xs font-mono uppercase tracking-wide text-on-surface-variant">Independent from port risk</p>
        <div className="flex items-start gap-3 rounded border bg-surface-low p-4 mt-4">
          <HelpCircle size={18} className="mt-0.5 text-on-surface-variant shrink-0" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-on-surface">IP reputation not available for this scan.</p>
            <p className="mt-1 text-sm leading-6 text-on-surface-variant">Threat intelligence was not available when this scan was created or the provider returned no data. UNKNOWN ≠ CLEAN.</p>
          </div>
        </div>
      </Card>
    );
  }

  const isUnavailable = reputation.reputation === 'unavailable';
  const isUnknown = reputation.reputation === 'unknown';

  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <p className="eyebrow mb-2">{titleEyebrow ?? 'IP reputation'}</p>
          <p className="text-xs font-mono uppercase tracking-wide text-on-surface-variant">IP reputation — independent from port risk</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <p className="font-display text-2xl font-bold">{reputation.reputation.toUpperCase()}</p>
            <ReputationBadge reputation={reputation.reputation} />
            {!isUnavailable && !isUnknown && <ConfidenceBadge confidence={reputation.confidence} />}
          </div>
          <p className="mt-2 text-sm text-on-surface-variant">
            {isUnavailable && 'Provider unavailable or IP not checked. UNAVAILABLE ≠ CLEAN.'}
            {isUnknown && 'No reputation data reported for this IP. UNKNOWN ≠ CLEAN.'}
            {reputation.reputation === 'clean' && 'No abuse reported for this IP.'}
            {reputation.reputation === 'suspicious' && `${reputation.reports} abuse report${reputation.reports === 1 ? '' : 's'} • flagged as suspicious.`}
            {reputation.reputation === 'malicious' && `${reputation.reports} abuse report${reputation.reports === 1 ? '' : 's'} • flagged as malicious.`}
          </p>
        </div>
        <Badge tone="primary"><Globe size={12} className="mr-1" aria-hidden="true" />{reputation.provider}</Badge>
      </div>

      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded border bg-surface-low p-4">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Globe size={14} aria-hidden="true" /> IP</p>
          <p className="mt-2 font-mono text-sm font-semibold text-on-surface break-all">{reputation.ip}</p>
          <p className="mt-1 text-xs text-on-surface-variant">Reports: {reputation.reports}</p>
        </div>
        <div className="rounded border bg-surface-low p-4">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Flag size={14} aria-hidden="true" /> Country / ASN</p>
          <p className="mt-2 font-mono text-sm font-semibold text-on-surface">{reputation.country ?? '—'} {reputation.asn ? `· AS${reputation.asn}` : ''}</p>
          <p className="mt-1 text-xs text-on-surface-variant">ASN: {reputation.asn ?? '—'}</p>
        </div>
        <div className="rounded border bg-surface-low p-4">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Building size={14} aria-hidden="true" /> Organization</p>
          <p className="mt-2 text-sm font-semibold text-on-surface break-words">{reputation.organization ?? reputation.isp ?? '—'}</p>
          <p className="mt-1 text-xs text-on-surface-variant break-words">{reputation.isp ?? ''}</p>
        </div>
        <div className="rounded border bg-surface-low p-4">
          <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Clock size={14} aria-hidden="true" /> Last reported</p>
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

function ThreatIntelligenceCard({ bundle, titleEyebrow }: { bundle: ThreatIntelligenceBundle | null | undefined; titleEyebrow?: string }) {
  if (!bundle || !bundle.providers || bundle.providers.length === 0) {
    return (
      <Card className="p-5">
        <p className="eyebrow mb-2">{titleEyebrow ?? 'Threat intelligence'}</p>
        <p className="text-xs font-mono uppercase tracking-wide text-on-surface-variant">Independent evidence from enabled providers</p>
        <div className="flex items-start gap-3 rounded border bg-surface-low p-4 mt-4">
          <HelpCircle size={18} className="mt-0.5 text-on-surface-variant shrink-0" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-on-surface">Threat intelligence was not available when this scan was created.</p>
            <p className="mt-1 text-sm leading-6 text-on-surface-variant">No providers were checked or no evidence was returned. UNKNOWN ≠ CLEAN · UNAVAILABLE ≠ CLEAN.</p>
          </div>
        </div>
      </Card>
    );
  }
  const overall = bundle.summary?.overall_reputation ?? 'unknown';
  // Gracefully handle single-provider case
  const isMixed = bundle.providers.length > 1;
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <p className="eyebrow mb-2">{titleEyebrow ?? 'Threat intelligence'}</p>
          <p className="text-xs font-mono uppercase tracking-wide text-on-surface-variant">Evidence, not verdict — providers are independent {isMixed ? '· multi-provider' : '· single provider'}</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <p className="font-display text-2xl font-bold">{overall.toUpperCase()}</p>
            <ReputationBadge reputation={overall as IPReputationResult['reputation']} />
            <Badge tone="primary"><Activity size={12} className="mr-1" aria-hidden="true" />{bundle.sources_available}/{bundle.sources_checked} providers</Badge>
          </div>
          <p className="mt-2 text-sm text-on-surface-variant">
            Overall {overall} · Evidence confidence {bundle.summary?.evidence_confidence ?? bundle.confidence} · Checked {bundle.checked_at ? formatDate(bundle.checked_at) : '—'}
          </p>
          <p className="mt-1 text-xs text-on-surface-variant/70">UNKNOWN does not mean CLEAN · UNAVAILABLE does not mean CLEAN · HoneyPot uses DNS HTTP:BL, not scraping</p>
        </div>
      </div>

      <div className="mt-6 space-y-3">
        {bundle.providers.map((p: ProviderEvidence) => (
          <div key={p.provider} className="rounded border bg-surface-low p-4">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <p className="text-xs font-medium uppercase tracking-wide text-on-surface-variant flex items-center gap-2"><Radio size={14} aria-hidden="true" /> {p.provider}</p>
              <div className="flex items-center gap-2 flex-wrap">
                <ReputationBadge reputation={p.reputation} />
                {p.confidence && p.confidence !== 'none' && <ConfidenceBadge confidence={p.confidence} />}
                <Badge tone={p.status === 'available' ? 'success' : p.status === 'unknown' ? 'primary' : 'warning'}>{p.status}</Badge>
              </div>
            </div>
            <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4 text-sm">
              <div>
                <p className="text-xs uppercase tracking-wide text-on-surface-variant">Reputation</p>
                <p className="font-mono font-semibold capitalize">{p.reputation}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-on-surface-variant">Confidence</p>
                <p className="font-mono font-semibold">{p.confidence ?? '—'}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-on-surface-variant">Threat score</p>
                <p className="font-mono font-semibold">{String(p.threat_score ?? (p.evidence as Record<string, unknown> | null)?.threat_score ?? '—')}</p>
              </div>
              <div>
                <p className="text-xs uppercase tracking-wide text-on-surface-variant">Days since activity / Last seen</p>
                <p className="font-mono font-semibold">{String(p.days_since_activity ?? (p.evidence as Record<string, unknown> | null)?.days_since_activity ?? '—')} {p.last_seen ? `· ${formatDate(p.last_seen)}` : ''}</p>
              </div>
            </div>
            {(p.visitor_type !== null && p.visitor_type !== undefined) || (p.visitor_type_name) ? (
              <div className="mt-2 text-sm">
                <p className="text-xs uppercase tracking-wide text-on-surface-variant">Visitor type</p>
                <p className="font-mono break-words">{p.visitor_type_name ?? p.visitor_type} {p.categories && p.categories.length ? `· ${p.categories.join(', ')}` : ''}</p>
              </div>
            ) : null}
            {p.reason && (
              <p className="mt-2 text-xs font-mono text-on-surface-variant/70">Reason: {p.reason}</p>
            )}
            <p className="mt-1 text-xs font-mono text-on-surface-variant/70">Checked: {p.checked_at ? formatDate(p.checked_at) : '—'}</p>
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
    // Basic frontend validation mirrors backend but does not replace it
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

  const getPortsScanned = () => {
    if (scanMode === 'quick') return QUICK_SCAN_PORTS.length;
    if (scanMode === 'common') return `${COMMON_SCAN_PORTS.length} defined · up to 100 scanned`;
    return customPorts.split(',').filter((p) => p.trim().length > 0).length;
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
    <>
      <PageHeader
        eyebrow="Security operations"
        title="Security Scan"
        description="Analyze publicly reachable network exposure and available threat intelligence for a domain or public IP. Port risk, IP reputation, and overall threat are separate signals."
        actions={
          <Button variant="secondary" onClick={handleToggleHistory} disabled={isScanning && !showHistory} aria-label={showHistory ? 'Back to security scan' : 'View scan history'}>
            {showHistory ? <ArrowLeft size={16} aria-hidden="true" /> : <History size={16} aria-hidden="true" />}
            {showHistory ? 'Back to scan' : 'History'}
          </Button>
        }
      />
      {/* Tutorial link — helps users understand the tool BEFORE using it */}
      <Card className="p-3 flex items-center justify-between gap-3 border-primary/20 bg-primary/[0.03] mt-4">
        <p className="text-sm font-medium text-on-surface flex items-center gap-2">
          <span className="grid h-7 w-7 place-items-center rounded bg-primary/15 text-primary shrink-0"><BookOpen size={14} /></span>
          Learn what ports are
        </p>
        <Link to="/tutorials/port-scanner/what-is-a-port" className="inline-flex items-center gap-1 text-sm font-semibold text-primary hover:underline focus:outline-none focus:ring-2 focus:ring-primary/60 rounded px-1">
          Open tutorial <ArrowRight size={14} />
        </Link>
      </Card>

      {!showHistory ? (
        <>
          {/* ── Form + What will be checked ── */}
          <div className="grid gap-5 xl:grid-cols-[1.05fr_0.95fr]">
            <Card className="p-5">
              <h2 className="eyebrow">Security scan</h2>
              <form onSubmit={handleScan} className="mt-4 grid gap-5" noValidate>
                <div className="grid gap-2">
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
                    className="h-11 rounded border bg-surface-low px-3 placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 disabled:opacity-60"
                  />
                  <p id="target-help" className="text-xs leading-5 text-on-surface-variant">
                    Enter a domain or public IP address. CyberShield will analyze its publicly reachable network exposure and available threat intelligence. Private or local targets are blocked.
                  </p>
                </div>

                <fieldset className="grid gap-3" disabled={isScanning} aria-describedby="profile-help">
                  <legend className="text-sm font-medium text-on-surface">Scan profile</legend>
                  <div className="grid gap-2 sm:grid-cols-3">
                    {(Object.keys(PROFILE_META) as ScanMode[]).map((mode) => (
                      <button
                        key={mode}
                        type="button"
                        onClick={() => setScanMode(mode)}
                        disabled={isScanning}
                        aria-pressed={scanMode === mode}
                        aria-label={`${PROFILE_META[mode].label}: ${PROFILE_META[mode].detail}`}
                        className={`rounded border px-3 py-3 text-left transition focus:outline-none focus:ring-2 focus:ring-primary/60 ${
                          scanMode === mode
                            ? 'border-primary/40 bg-primary/10 text-primary'
                            : 'border-outline-variant/70 bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface'
                        }`}
                      >
                        <p className="text-sm font-semibold">{PROFILE_META[mode].label}</p>
                        <p className="mt-1 text-xs leading-4 text-on-surface-variant">{PROFILE_META[mode].detail}</p>
                      </button>
                    ))}
                  </div>
                  <p id="profile-help" className="text-xs leading-5 text-on-surface-variant">Quick uses 20 ports; Standard uses a broader set (up to 100 ports enforced server-side); Custom lets you specify ports.</p>
                </fieldset>

                {scanMode === 'custom' && (
                  <div className="grid gap-2">
                    <label htmlFor="custom-ports" className="text-sm font-medium text-on-surface">Custom ports (comma-separated)</label>
                    <textarea
                      id="custom-ports"
                      rows={3}
                      placeholder="22, 80, 443, 8080"
                      value={customPorts}
                      onChange={(e) => setCustomPorts(e.target.value)}
                      disabled={isScanning}
                      aria-describedby="custom-ports-help"
                      className="rounded border bg-surface-low p-3 font-mono text-sm text-on-surface placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20 resize-none disabled:opacity-60"
                    />
                    <p id="custom-ports-help" className="text-xs leading-5 text-on-surface-variant">
                      Enter up to 100 ports (1–65535). Duplicates will be removed automatically.
                    </p>
                  </div>
                )}

                <Button type="submit" disabled={isScanning || !target.trim()} className="w-full" aria-label="Start security scan">
                  {isScanning ? (
                    <> <Loader2 size={16} className="animate-spin mr-2" aria-hidden="true" /> Analyzing… </>
                  ) : (
                    <> <Play size={16} className="mr-2" aria-hidden="true" /> Start Security Scan </>
                  )}
                </Button>

                {error && (
                  <div role="alert" className="flex items-start gap-2 rounded border border-destructive/20 bg-destructive/10 p-3 text-sm text-destructive">
                    <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true" /> <span>{error}</span>
                  </div>
                )}
              </form>

              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Scan configuration</p>
                <dl className="grid grid-cols-2 gap-2 text-sm">
                  <dt className="text-on-surface-variant">Target</dt>
                  <dd className="font-mono text-on-surface break-all">{target || '—'}</dd>
                  <dt className="text-on-surface-variant">Profile</dt>
                  <dd className="font-mono text-on-surface capitalize">{scanMode === 'quick' ? 'Quick' : scanMode === 'common' ? 'Standard' : 'Custom'}</dd>
                  <dt className="text-on-surface-variant">Ports to scan</dt>
                  <dd className="font-mono text-on-surface">{String(getPortsScanned())}</dd>
                  <dt className="text-on-surface-variant">Method</dt>
                  <dd className="font-mono text-on-surface">TCP connect</dd>
                </dl>
              </div>
            </Card>

            <div className="grid gap-5 content-start">
              <Card className="p-5">
                <h3 className="eyebrow mb-3 flex items-center gap-2"><Info size={14} aria-hidden="true" /> What will be checked</h3>
                <ul className="space-y-3">
                  <li className="flex gap-3 rounded border bg-surface-low p-3">
                    <span className="grid h-8 w-8 place-items-center rounded bg-primary/10 text-primary shrink-0"><Radio size={16} aria-hidden="true" /></span>
                    <div>
                      <p className="text-sm font-semibold">Port Exposure</p>
                      <p className="text-xs leading-5 text-on-surface-variant">Finds publicly reachable network services.</p>
                    </div>
                  </li>
                  <li className="flex gap-3 rounded border bg-surface-low p-3">
                    <span className="grid h-8 w-8 place-items-center rounded bg-primary/10 text-primary shrink-0"><Globe size={16} aria-hidden="true" /></span>
                    <div>
                      <p className="text-sm font-semibold">IP Reputation</p>
                      <p className="text-xs leading-5 text-on-surface-variant">Checks available reputation information for the resolved public IP.</p>
                    </div>
                  </li>
                  <li className="flex gap-3 rounded border bg-surface-low p-3">
                    <span className="grid h-8 w-8 place-items-center rounded bg-primary/10 text-primary shrink-0"><Database size={16} aria-hidden="true" /></span>
                    <div>
                      <p className="text-sm font-semibold">Threat Intelligence</p>
                      <p className="text-xs leading-5 text-on-surface-variant">Collects available security evidence from configured intelligence providers.</p>
                    </div>
                  </li>
                  <li className="flex gap-3 rounded border bg-surface-low p-3">
                    <span className="grid h-8 w-8 place-items-center rounded bg-primary/10 text-primary shrink-0"><Shield size={16} aria-hidden="true" /></span>
                    <div>
                      <p className="text-sm font-semibold">Overall Threat</p>
                      <p className="text-xs leading-5 text-on-surface-variant">Combines the collected evidence into CyberShield’s derived threat assessment.</p>
                    </div>
                  </li>
                </ul>
                <div className="mt-4 rounded border border-amber-500/20 bg-amber-500/10 p-3">
                  <p className="text-xs font-semibold text-amber-700 dark:text-amber-300 flex items-center gap-1.5"><AlertTriangle size={12} aria-hidden="true" /> Important</p>
                  <p className="mt-1 text-xs leading-5 text-on-surface-variant">Port Risk, IP Reputation, and Overall Threat are <span className="font-semibold text-on-surface">different signals</span>. A low port risk does not mean the IP is clean, and UNKNOWN does not mean safe.</p>
                </div>
              </Card>

              {/* Right-side scanning or empty or summary */}
              {isScanning ? (
                <ScanningState elapsedSeconds={elapsedSeconds} isSlow={isSlow} />
              ) : result ? (
                <Card className="p-5">
                  <p className="eyebrow mb-2">Latest scan summary</p>
                  <p className="text-sm leading-6 text-on-surface-variant">
                    Scanned <code className="font-mono break-all">{result.target}</code>
                    {result.resolved_ip && <span> · Resolved to <code className="font-mono break-all">{result.resolved_ip}</code></span>}
                    {' · '}{result.scan_duration_ms}ms · {result.ports_scanned} ports
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs font-mono">
                    <span className="rounded bg-surface-low px-2 py-1 border">Risk: {result.risk_level}</span>
                    <span className="rounded bg-surface-low px-2 py-1 border">Open: {result.open_ports.filter(p=>p.state==='open').length}</span>
                  </div>
                </Card>
              ) : (
                <Card className="p-5">
                  <div className="flex flex-col items-center justify-center py-6 text-center">
                    <span className="mb-3 grid h-12 w-12 place-items-center rounded-full bg-primary/10 text-primary"><ShieldCheck size={22} aria-hidden="true" /></span>
                    <h3 className="font-display text-base font-semibold">No security scan yet</h3>
                    <p className="mt-2 max-w-sm text-sm leading-6 text-on-surface-variant">Enter a public domain or IP address above to analyze network exposure and available threat intelligence.</p>
                  </div>
                </Card>
              )}
            </div>
          </div>

          {/* ── Results hierarchy (A-E) ── */}
          {isScanning ? null : result ? (
            <div className="mt-6 grid gap-5">
              {/* A. Overall Threat — most prominent */}
              <OverallThreatCard assessment={result.threat_assessment ?? null} />
              {/* B. Port Risk */}
              <PortRiskCard result={result} />
              {/* C. IP Reputation */}
              <IPReputationCard reputation={result.ip_reputation ?? null} titleEyebrow="IP reputation" />
              {/* D. Threat Intelligence */}
              <ThreatIntelligenceCard bundle={result.threat_intelligence ?? null} titleEyebrow="Threat intelligence" />
              {/* E. Technical Port Details */}
              <Card className="">
                <div className="border-b px-5 py-4 flex items-center justify-between gap-3">
                  <p className="font-display font-semibold flex items-center gap-2">
                    <Layers size={18} className="text-primary" aria-hidden="true" /> Technical port details
                  </p>
                  <span className="text-xs font-mono text-on-surface-variant">{result.open_ports.length} open · {result.closed_ports} closed · {result.filtered_ports} filtered</span>
                </div>
                <div className="p-4">
                  {result.open_ports.length > 0 ? (
                    <>
                      <div className="mb-4 flex flex-wrap gap-2 text-sm text-on-surface-variant">
                        <span className="px-2 py-1 rounded bg-surface-low font-mono border">Open: {result.open_ports.filter(p => p.state === 'open').length}</span>
                        <span className="px-2 py-1 rounded bg-surface-low font-mono border">Closed: {result.closed_ports}</span>
                        <span className="px-2 py-1 rounded bg-surface-low font-mono border">Filtered: {result.filtered_ports}</span>
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
            </div>
          ) : null}
        </>
      ) : (
        <>
          <Card className="p-5">
            <div className="flex items-center justify-between gap-4 flex-wrap">
              <p className="font-display text-lg font-semibold flex items-center gap-2"><History size={18} className="text-primary" aria-hidden="true" /> Scan history</p>
              <Button variant="secondary" disabled={historyLoading} onClick={() => fetchHistory(historyPage)} aria-label="Refresh scan history">
                {historyLoading ? <Loader2 size={16} className="animate-spin" aria-hidden="true" /> : <Search size={16} aria-hidden="true" />}
                Refresh
              </Button>
            </div>
            <p className="mt-2 text-sm text-on-surface-variant">Your previous security scans, newest first. Select a scan to view full details including threat assessment, IP reputation, and threat intelligence where available.</p>

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
                  <Search size={26} aria-hidden="true" />
                </span>
                <h2 className="font-display text-lg font-semibold">No security scans yet</h2>
                <p className="mt-2 max-w-sm text-sm leading-6 text-on-surface-variant">
                  Completed scans will appear here. Run your first security scan to start building history.
                </p>
                <Button className="mt-5" onClick={handleToggleHistory}>
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
                <div className="mt-6 overflow-x-auto rounded border">
                  <table className="w-full min-w-[720px] text-left text-sm">
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
                          <td className="px-4 py-3 font-mono font-medium text-on-surface break-all">{item.target}</td>
                          <td className="px-4 py-3 font-mono text-on-surface-variant break-all">{item.resolved_ip ?? '—'}</td>
                          <td className="px-4 py-3 text-on-surface-variant">{formatDate(item.created_at)}</td>
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
            <Card className="mt-5 p-5">
              <div className="flex items-center gap-2 text-sm text-on-surface-variant" role="status" aria-live="polite">
                <Loader2 size={16} className="animate-spin" aria-hidden="true" /> Loading scan detail…
              </div>
              {detailSlow && <div className="mt-4"><SlowRequestNotice elapsedSeconds={detailElapsed} /></div>}
            </Card>
          )}

          {detailError && (
            <Card className="mt-5 p-5">
              <div className="flex items-start gap-3 rounded border border-destructive/20 bg-destructive/10 p-4" role="alert">
                <AlertCircle size={18} className="mt-0.5 shrink-0 text-destructive" aria-hidden="true" />
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
              <div className="mt-6 grid gap-5">
                {/* Historical hierarchy same order A-E */}
                <OverallThreatCard assessment={detail.threat_assessment ?? null} />
                <PortRiskCard result={detail} />
                <IPReputationCard reputation={detail.ip_reputation ?? null} titleEyebrow="IP reputation — historical" />
                <ThreatIntelligenceCard bundle={detail.threat_intelligence ?? null} titleEyebrow="Threat intelligence — historical" />

                <Card className="">
                  <div className="border-b px-5 py-4 flex items-center justify-between gap-3 flex-wrap">
                    <p className="font-display font-semibold flex items-center gap-2">
                      <Layers size={18} className="text-primary" aria-hidden="true" /> Port findings · {detail.open_ports.length} ports
                    </p>
                    <span className="text-xs font-mono text-on-surface-variant">Historical · {formatDate(detail.created_at)}</span>
                  </div>
                  <div className="p-4">
                    <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <div className="rounded border bg-surface-low p-3">
                        <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Target size={14} aria-hidden="true" /> Target</p>
                        <p className="mt-1 font-mono text-sm font-semibold text-on-surface break-all">{detail.target}</p>
                      </div>
                      <div className="rounded border bg-surface-low p-3">
                        <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><HardDrive size={14} aria-hidden="true" /> Resolved IP</p>
                        <p className="mt-1 font-mono text-sm font-semibold text-on-surface break-all">{detail.resolved_ip ?? '—'}</p>
                      </div>
                      <div className="rounded border bg-surface-low p-3">
                        <p className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-on-surface-variant"><Clock size={14} aria-hidden="true" /> Duration</p>
                        <p className="mt-1 font-mono text-sm font-semibold text-on-surface">{detail.scan_duration_ms ?? '—'}ms</p>
                      </div>
                      <div className="rounded border bg-surface-low p-3">
                        <p className="text-xs font-medium uppercase tracking-wide text-on-surface-variant">Scanned</p>
                        <p className="mt-1 font-mono text-sm font-semibold text-on-surface">{detail.ports_scanned} ports</p>
                      </div>
                    </div>
                    <div className="mb-4 flex flex-wrap gap-2 text-xs font-mono">
                      <span className="rounded bg-surface-low px-3 py-1 border">Open: {detail.open_port_count}</span>
                      <span className="rounded bg-surface-low px-3 py-1 border">Closed: {detail.closed_port_count}</span>
                      <span className="rounded bg-surface-low px-3 py-1 border">Filtered: {detail.filtered_port_count}</span>
                      <span className="rounded bg-surface-low px-3 py-1 border capitalize">Status: {detail.status}</span>
                    </div>
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
                <div className="flex justify-end">
                  <Button variant="secondary" onClick={() => setDetail(null)} aria-label="Close scan detail"><ArrowLeft size={16} aria-hidden="true" /> Close detail</Button>
                </div>
              </div>
            </>
          )}
        </>
      )}
    </>
  );
}
