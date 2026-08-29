import {
  AlertCircle,
  AlertTriangle,
  ArrowUpRight,
  HelpCircle,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Zap,
  FileText,
  Radio,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { Badge, Button, Card } from './ui';
import type { DashboardActivity } from '../types';

// ---------------------------------------------------------------------------
// Compact relative time — Just now, 12m ago, 4h ago, 2d ago
// Never fabricates, handles invalid/missing gracefully
// ---------------------------------------------------------------------------
function formatRelative(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  if (diffMs < 0) return 'Just now';
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

// ---------------------------------------------------------------------------
// Icon / tone selection — never color-only, always text label
// ---------------------------------------------------------------------------
type Visual = { icon: typeof ScanSearch; tone: 'success' | 'primary' | 'warning' | 'danger'; label: string };

function getVisual(a: DashboardActivity): Visual {
  if (a.status === 'failed') {
    return { icon: AlertCircle, tone: 'danger', label: 'FAILED' };
  }
  const ta = a.threat_assessment;
  if (ta) {
    if (ta.level === 'critical') return { icon: ShieldAlert, tone: 'danger', label: 'CRITICAL' };
    if (ta.level === 'high') return { icon: AlertTriangle, tone: 'danger', label: 'HIGH' };
    if (ta.level === 'medium') return { icon: AlertCircle, tone: 'warning', label: 'MEDIUM' };
    if (ta.level === 'low') return { icon: ShieldCheck, tone: 'success', label: 'LOW' };
  }
  const rep = a.ip_reputation?.reputation ?? null;
  if (rep) {
    if (rep === 'malicious') return { icon: ShieldX, tone: 'danger', label: 'MALICIOUS IP' };
    if (rep === 'suspicious') return { icon: AlertTriangle, tone: 'warning', label: 'SUSPICIOUS IP' };
    if (rep === 'clean') return { icon: ShieldCheck, tone: 'success', label: 'CLEAN IP' };
    if (rep === 'unknown') return { icon: HelpCircle, tone: 'primary', label: 'UNKNOWN IP' };
    if (rep === 'unavailable') return { icon: HelpCircle, tone: 'primary', label: 'UNAVAILABLE IP' };
  }
  const tiOverall = a.threat_intelligence?.summary?.overall_reputation ?? null;
  if (tiOverall && tiOverall !== 'unknown' && tiOverall !== 'unavailable') {
    if (tiOverall === 'malicious') return { icon: Radio, tone: 'danger', label: 'MALICIOUS' };
    if (tiOverall === 'suspicious') return { icon: Radio, tone: 'warning', label: 'SUSPICIOUS' };
    if (tiOverall === 'clean') return { icon: ShieldCheck, tone: 'success', label: 'CLEAN' };
  }
  const risk = (a.risk_level ?? '').toLowerCase();
  if (risk === 'critical') return { icon: ShieldAlert, tone: 'danger', label: 'CRITICAL' };
  if (risk === 'high') return { icon: AlertTriangle, tone: 'danger', label: 'HIGH' };
  if (risk === 'medium') return { icon: AlertCircle, tone: 'warning', label: 'MEDIUM' };
  if (risk === 'low') return { icon: ShieldCheck, tone: 'success', label: 'LOW' };
  if (a.type === 'report') return { icon: FileText, tone: 'primary', label: 'REPORT' };
  return { icon: ScanSearch, tone: 'primary', label: 'SCAN' };
}

// ---------------------------------------------------------------------------
// Threat signal line — priority: Overall Threat -> IP Reputation -> Port Risk -> Threat Intel
// UNKNOWN / UNAVAILABLE never become SAFE
// ---------------------------------------------------------------------------
function getSignalLine(a: DashboardActivity): { text: string; tone: 'success' | 'primary' | 'warning' | 'danger' } | null {
  if (a.threat_assessment) {
    const level = a.threat_assessment.level?.toUpperCase() ?? 'UNKNOWN';
    const toneMap: Record<string, 'success' | 'primary' | 'warning' | 'danger'> = {
      low: 'success',
      medium: 'warning',
      high: 'danger',
      critical: 'danger',
    };
    const tone = toneMap[a.threat_assessment.level] ?? 'primary';
    return { text: `Overall threat: ${level}`, tone };
  }
  const isPortScan = a.type === 'port_scan' || a.type === 'port_scans' || (!!a.resolved_ip && a.type !== 'report');
  // 2. IP reputation
  if (a.ip_reputation) {
    const rep = a.ip_reputation.reputation?.toUpperCase() ?? 'UNKNOWN';
    const toneMap: Record<string, 'success' | 'primary' | 'warning' | 'danger'> = {
      clean: 'success',
      suspicious: 'warning',
      malicious: 'danger',
      unknown: 'primary',
      unavailable: 'primary',
    };
    const tone = toneMap[a.ip_reputation.reputation] ?? 'primary';
    return { text: `IP reputation: ${rep}`, tone };
  }
  // 3. Port risk / generic risk
  if (a.risk_level) {
    const r = a.risk_level.toUpperCase();
    const toneMap: Record<string, 'success' | 'primary' | 'warning' | 'danger'> = {
      low: 'success',
      medium: 'warning',
      high: 'danger',
      critical: 'danger',
      unknown: 'primary',
    };
    const tone = toneMap[a.risk_level.toLowerCase()] ?? 'primary';
    const prefix = isPortScan ? 'Port risk' : 'Risk';
    return { text: `${prefix}: ${r}`, tone };
  }
  // 4. Threat intelligence overall
  const ti = a.threat_intelligence?.summary?.overall_reputation;
  if (ti) {
    const rep = ti.toUpperCase();
    const toneMap: Record<string, 'success' | 'primary' | 'warning' | 'danger'> = {
      clean: 'success',
      suspicious: 'warning',
      malicious: 'danger',
      unknown: 'primary',
      unavailable: 'primary',
    };
    const tone = toneMap[ti] ?? 'primary';
    return { text: `Threat intel: ${rep}`, tone };
  }
  if (isPortScan) {
    return { text: 'Overall threat unavailable', tone: 'primary' };
  }
  return null;
}

function getTitle(a: DashboardActivity): string {
  if (a.type === 'report') return 'Report generated';
  if (a.status === 'failed') return 'Security scan failed';
  const ta = a.threat_assessment;
  if (ta?.level === 'critical') return 'Critical threat assessment';
  if (a.ip_reputation?.reputation === 'malicious') return 'Malicious IP detected';
  if (a.ip_reputation?.reputation === 'suspicious') return 'Suspicious IP detected';
  if (
    a.threat_intelligence &&
    (a.threat_intelligence.summary?.overall_reputation === 'malicious' ||
      a.threat_intelligence.summary?.overall_reputation === 'suspicious')
  ) {
    return 'Threat intelligence available';
  }
  const risk = (a.risk_level ?? '').toLowerCase();
  if (risk === 'high' || risk === 'critical') return 'High-risk exposure detected';
  if (a.type === 'port_scan') return 'Security scan completed';
  if (a.message) {
    if (a.message.startsWith('Security scan')) return a.message;
    if (a.message.startsWith('Website scan')) return 'Security scan completed';
    return a.message;
  }
  return 'Security scan completed';
}

// ---------------------------------------------------------------------------
// Internal reusable row — responsive: desktop time at right, mobile time below
// ---------------------------------------------------------------------------
function ActivityRow({ activity }: { activity: DashboardActivity }) {
  const vis = getVisual(activity);
  const Icon = vis.icon;
  const signal = getSignalLine(activity);
  const title = getTitle(activity);
  const rel = formatRelative(activity.created_at);
  const targetText = activity.target ?? activity.message ?? '—';

  const toneBg: Record<string, string> = {
    success: 'bg-success/15 text-success',
    warning: 'bg-warning/15 text-warning',
    danger: 'bg-danger/15 text-danger',
    primary: 'bg-primary/15 text-primary',
  };

  return (
    <li className="flex gap-3 py-3.5 first:pt-3 last:pb-2 hover:bg-surface-high/20 -mx-1 px-1 rounded transition-colors">
      <span
        className={`mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-full border border-transparent ${toneBg[vis.tone]}`}
        aria-hidden="true"
      >
        <Icon size={14} strokeWidth={1.9} />
      </span>

      {/* Content grows, truncated */}
      <div className="min-w-0 flex-1">
        {/* Row inner: content + desktop time */}
        <div className="flex gap-3">
          <div className="min-w-0 flex-1 space-y-0.5">
            <p className="truncate text-[13px] font-semibold leading-5 text-on-surface">{title}</p>
            <p
              className="truncate font-mono text-xs leading-4 text-on-surface-variant"
              title={targetText}
            >
              {targetText}
            </p>

            {/* Badge — compact, wraps, never overflows */}
            <div className="flex flex-wrap pt-1">
              {signal ? (
                <Badge tone={signal.tone}>{signal.text}</Badge>
              ) : (
                <Badge tone="primary">No threat signal</Badge>
              )}
            </div>

            {/* Mobile timestamp — stacked */}
            {rel && (
              <p className="pt-1 font-mono text-[11px] uppercase tracking-wide text-on-surface-variant/60 sm:hidden">
                {rel}
              </p>
            )}
          </div>

          {/* Desktop timestamp — right-aligned */}
          {rel && (
            <span className="hidden shrink-0 whitespace-nowrap pt-0.5 font-mono text-[11px] uppercase tracking-wide text-on-surface-variant/60 sm:block">
              {rel}
            </span>
          )}
        </div>
      </div>
    </li>
  );
}

// ---------------------------------------------------------------------------
export interface SecurityActivityProps {
  readonly activities: readonly DashboardActivity[];
  readonly loading?: boolean;
  readonly error?: string | null;
  readonly onRetry?: () => void;
  readonly maxItems?: number;
}

export function SecurityActivity({ activities, loading = false, error = null, onRetry, maxItems = 6 }: SecurityActivityProps) {
  const display = activities.slice(0, maxItems);

  if (loading) {
    return (
      <Card className="overflow-hidden p-4 sm:p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="eyebrow">Security activity</h2>
            <p className="mt-1 text-xs leading-4 text-on-surface-variant">Recent security events</p>
          </div>
          <span className="h-5 w-16 animate-pulse rounded bg-surface-high" aria-hidden="true" />
        </div>
        <div className="mt-3 divide-y divide-outline-variant/30" aria-busy="true" aria-live="polite">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex gap-3 py-3.5">
              <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-full bg-surface-high animate-pulse" aria-hidden="true" />
              <div className="min-w-0 flex-1 space-y-2 pt-1">
                <div className="h-3 w-2/3 rounded bg-surface-high animate-pulse" />
                <div className="h-3 w-1/2 rounded bg-surface-high/70 animate-pulse" />
                <div className="h-4 w-28 rounded bg-surface-high/60 animate-pulse" />
              </div>
              <span className="hidden sm:block h-3 w-10 shrink-0 rounded bg-surface-high/60 animate-pulse" aria-hidden="true" />
            </div>
          ))}
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="overflow-hidden p-4 sm:p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="eyebrow">Security activity</h2>
            <p className="mt-1 text-xs leading-4 text-on-surface-variant">Recent security events</p>
          </div>
          <Link
            to="/port-scanner"
            className="inline-flex shrink-0 items-center gap-1 text-xs font-semibold text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 rounded"
          >
            View all <ArrowUpRight size={12} aria-hidden="true" />
          </Link>
        </div>
        <div className="mt-4 rounded-lg border border-danger/20 bg-danger/10 p-4 text-center" role="alert">
          <p className="text-sm font-semibold text-danger">Security activity unavailable</p>
          <p className="mt-1 text-xs leading-5 text-on-surface-variant">Unable to load recent scan activity.</p>
          {onRetry && (
            <Button variant="secondary" className="mt-3 h-8 px-3 text-xs" onClick={onRetry}>
              Retry
            </Button>
          )}
        </div>
      </Card>
    );
  }

  if (activities.length === 0) {
    return (
      <Card className="overflow-hidden p-4 sm:p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="eyebrow">Security activity</h2>
            <p className="mt-1 text-xs leading-4 text-on-surface-variant">Recent security events</p>
          </div>
          <Link
            to="/port-scanner"
            className="inline-flex shrink-0 items-center gap-1 text-xs font-semibold text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60 rounded"
          >
            View all <ArrowUpRight size={12} aria-hidden="true" />
          </Link>
        </div>
        <div className="mx-auto mt-6 flex max-w-sm flex-col items-center pb-2 text-center">
          <span className="grid h-10 w-10 place-items-center rounded-full bg-primary/10 text-primary" aria-hidden="true">
            <ScanSearch size={18} />
          </span>
          <p className="mt-3 text-sm font-semibold text-on-surface">No security activity yet</p>
          <p className="mt-1 text-xs leading-5 text-on-surface-variant">
            Run your first security scan to start building your security history.
          </p>
          <Link
            to="/port-scanner"
            className="mt-4 inline-flex h-9 items-center justify-center gap-2 rounded bg-primary px-4 text-sm font-semibold text-primary-foreground hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
          >
            <Zap size={14} aria-hidden="true" />
            Start Security Scan
          </Link>
        </div>
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden p-4 sm:p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="eyebrow">Security activity</h2>
          <p className="mt-1 text-xs leading-4 text-on-surface-variant">Recent security events</p>
        </div>
        <Link
          to="/port-scanner"
          className="inline-flex shrink-0 items-center gap-1 rounded text-xs font-semibold text-primary hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60"
        >
          View all <ArrowUpRight size={12} aria-hidden="true" />
        </Link>
      </div>

      <ol className="mt-3 divide-y divide-outline-variant/30" role="list">
        {display.map((a, idx) => {
          const key = `${a.created_at ?? idx}-${a.target ?? getTitle(a)}-${idx}`;
          return <ActivityRow key={key} activity={a} />;
        })}
      </ol>
    </Card>
  );
}

// Compact inline variant for embed without Card chrome (kept for reuse)
export function SecurityActivityItem({ activity }: { activity: DashboardActivity }) {
  return <ActivityRow activity={activity} />;
}
