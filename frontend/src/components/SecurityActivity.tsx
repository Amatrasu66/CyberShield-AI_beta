import {
  AlertCircle,
  AlertTriangle,
  HelpCircle,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Zap,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { Badge, Button, Card } from './ui';
import type { DashboardActivity } from '../types';

// ---------------------------------------------------------------------------
// Relative timestamp — spec: Just now, 5 minutes ago, 2 hours ago, Yesterday, Aug 24, 2026
// Never fabricates, handles invalid/missing gracefully
// ---------------------------------------------------------------------------
function formatRelative(iso: string | null): string {
  if (!iso) return 'Unknown time';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return 'Unknown time';
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  if (diffMs < 0) return 'Just now';
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

// ---------------------------------------------------------------------------
// Visual mapping — never color-only, always text label
// ---------------------------------------------------------------------------
type Visual = { icon: typeof ScanSearch; tone: 'success' | 'primary' | 'warning' | 'danger'; label: string };

function getVisual(a: DashboardActivity): Visual {
  // Failed scan
  if (a.status === 'failed') {
    return { icon: AlertCircle, tone: 'danger', label: 'FAILED' };
  }
  // Overall threat takes highest priority
  const ta = a.threat_assessment;
  if (ta) {
    if (ta.level === 'critical') return { icon: ShieldAlert, tone: 'danger', label: 'CRITICAL' };
    if (ta.level === 'high') return { icon: AlertTriangle, tone: 'danger', label: 'HIGH' };
    if (ta.level === 'medium') return { icon: AlertCircle, tone: 'warning', label: 'MEDIUM' };
    if (ta.level === 'low') return { icon: ShieldCheck, tone: 'success', label: 'LOW' };
  }
  // IP reputation second priority — UNKNOWN/UNAVAILABLE must stay literal
  const rep = a.ip_reputation?.reputation ?? null;
  if (rep) {
    if (rep === 'malicious') return { icon: ShieldX, tone: 'danger', label: 'MALICIOUS IP' };
    if (rep === 'suspicious') return { icon: AlertTriangle, tone: 'warning', label: 'SUSPICIOUS IP' };
    if (rep === 'clean') return { icon: ShieldCheck, tone: 'success', label: 'CLEAN IP' };
    if (rep === 'unknown') return { icon: HelpCircle, tone: 'primary', label: 'UNKNOWN IP' };
    if (rep === 'unavailable') return { icon: HelpCircle, tone: 'primary', label: 'UNAVAILABLE IP' };
  }
  // Threat intelligence fallback
  const tiOverall = a.threat_intelligence?.summary?.overall_reputation ?? null;
  if (tiOverall && tiOverall !== 'unknown' && tiOverall !== 'unavailable') {
    if (tiOverall === 'malicious') return { icon: ShieldX, tone: 'danger', label: 'MALICIOUS' };
    if (tiOverall === 'suspicious') return { icon: AlertTriangle, tone: 'warning', label: 'SUSPICIOUS' };
    if (tiOverall === 'clean') return { icon: ShieldCheck, tone: 'success', label: 'CLEAN' };
  }
  // Port / generic risk
  const risk = (a.risk_level ?? '').toLowerCase();
  if (risk === 'critical') return { icon: ShieldAlert, tone: 'danger', label: 'CRITICAL' };
  if (risk === 'high') return { icon: AlertTriangle, tone: 'danger', label: 'HIGH' };
  if (risk === 'medium') return { icon: AlertCircle, tone: 'warning', label: 'MEDIUM' };
  if (risk === 'low') return { icon: ShieldCheck, tone: 'success', label: 'LOW' };
  // Report or generic
  if (a.type === 'report') return { icon: ShieldCheck, tone: 'primary', label: 'REPORT' };
  return { icon: ScanSearch, tone: 'primary', label: 'SCAN' };
}

// ---------------------------------------------------------------------------
// Threat signal line — priority: Overall Threat → IP Reputation → Port Risk → Threat Intel
// UNKNOWN / UNAVAILABLE never become SAFE
// ---------------------------------------------------------------------------
function getSignalLine(a: DashboardActivity): { text: string; tone: 'success' | 'primary' | 'warning' | 'danger' } | null {
  // 1. Overall threat — if present on port scan, always surface (most useful)
  if (a.threat_assessment) {
    const level = a.threat_assessment.level?.toUpperCase() ?? 'UNKNOWN';
    // Badge tone mirrors level
    const toneMap: Record<string, 'success' | 'primary' | 'warning' | 'danger'> = {
      low: 'success',
      medium: 'warning',
      high: 'danger',
      critical: 'danger',
    };
    const tone = toneMap[a.threat_assessment.level] ?? 'primary';
    // Compact: "Overall threat: HIGH" (score optional but not overload)
    return { text: `Overall threat: ${level}`, tone };
  }
  // No threat_assessment: for port scans we must be explicit, not fake SAFE
  const isPortScan = a.type === 'port_scan' || a.type === 'port_scans' || (!!a.resolved_ip && a.type !== 'report');
  if (isPortScan && a.threat_assessment === null && a.threat_assessment !== undefined) {
    // Port scan without threat_assessment ->Unavailable (do not show IP repro if we treat threat missing as signal)
    // But priority says fallback to IP reputation, so only show unavailable if we have no other signal?
    // We'll fall through to IP reputation first, and only show unavailable if nothing else available.
  }
  // 2. IP reputation
  if (a.ip_reputation) {
    const rep = a.ip_reputation.reputation?.toUpperCase() ?? 'UNKNOWN';
    // UNKNOWN / UNAVAILABLE stay literal
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
  if (isPortScan && a.ip_reputation === null) {
    // IP reputation explicitly unavailable — will be handled if risk not available? show fallback.
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
    // For port scans keep wording "Port risk", for others "Risk"
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
  // Missing threat assessment for port scan -> explicit unavailable
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
  if (a.threat_intelligence && (a.threat_intelligence.summary?.overall_reputation === 'malicious' || a.threat_intelligence.summary?.overall_reputation === 'suspicious')) {
    return 'Threat intelligence available';
  }
  const risk = (a.risk_level ?? '').toLowerCase();
  if (risk === 'high' || risk === 'critical') return 'High-risk exposure detected';
  // Default
  if (a.type === 'port_scan') return 'Security scan completed';
  if (a.message) {
    // Use stored message but strip verbose prefix for compactness
    if (a.message.startsWith('Security scan')) return a.message;
    if (a.message.startsWith('Website scan')) return 'Security scan completed';
    return a.message;
  }
  return 'Security scan completed';
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
  const hasMore = activities.length > maxItems;

  if (loading) {
    return (
      <Card className="p-5">
        <div className="flex items-center justify-between">
          <p className="font-display text-sm font-semibold uppercase tracking-wide">Security activity</p>
          <span className="h-5 w-16 animate-pulse rounded bg-surface-high" aria-hidden="true" />
        </div>
        <div className="mt-4 space-y-0 divide-y divide-outline-variant/30" aria-busy="true" aria-live="polite">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex gap-3 py-3.5">
              <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full bg-surface-high animate-pulse" aria-hidden="true" />
              <div className="min-w-0 flex-1 space-y-2">
                <div className="h-3 w-2/3 rounded bg-surface-high animate-pulse" />
                <div className="h-3 w-1/2 rounded bg-surface-high/70 animate-pulse" />
                <div className="h-4 w-28 rounded bg-surface-high/60 animate-pulse" />
              </div>
            </div>
          ))}
        </div>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className="p-5">
        <div className="flex items-center justify-between">
          <p className="font-display text-sm font-semibold uppercase tracking-wide">Security activity</p>
          <Link to="/port-scanner" className="text-xs font-semibold text-primary hover:underline">
            View all
          </Link>
        </div>
        <div className="mt-4 rounded border border-danger/20 bg-danger/10 p-4 text-center" role="alert">
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
      <Card className="p-6 text-center">
        <div className="flex items-center justify-between text-left">
          <p className="font-display text-sm font-semibold uppercase tracking-wide">Security activity</p>
          <Link to="/port-scanner" className="text-xs font-semibold text-primary hover:underline">
            View all
          </Link>
        </div>
        <div className="mx-auto mt-6 flex max-w-sm flex-col items-center">
          <span className="grid h-10 w-10 place-items-center rounded-full bg-primary/10 text-primary" aria-hidden="true">
            <ScanSearch size={18} />
          </span>
          <p className="mt-3 text-sm font-semibold">No security activity yet.</p>
          <p className="mt-1 text-xs leading-5 text-on-surface-variant">
            Run your first security scan to start building your security history.
          </p>
          <Link
            to="/port-scanner"
            className="mt-4 inline-flex h-9 items-center justify-center gap-2 rounded bg-primary px-4 text-sm font-semibold text-primary-foreground hover:brightness-110"
          >
            <Zap size={14} aria-hidden="true" />
            Start Security Scan
          </Link>
        </div>
      </Card>
    );
  }

  return (
    <Card className="p-5">
      <div className="flex items-center justify-between">
        <p className="font-display text-sm font-semibold uppercase tracking-wide">Security activity</p>
        <Link to="/port-scanner" className="text-xs font-semibold text-primary hover:underline">
          View all
        </Link>
      </div>
      <ol className="mt-3 divide-y divide-outline-variant/30" role="list">
        {display.map((a, idx) => {
          const vis = getVisual(a);
          const Icon = vis.icon;
          const signal = getSignalLine(a);
          const title = getTitle(a);
          const key = `${a.created_at ?? idx}-${a.target ?? title}-${idx}`;
          const toneBg: Record<string, string> = {
            success: 'bg-success/15 text-success',
            warning: 'bg-warning/15 text-warning',
            danger: 'bg-danger/15 text-danger',
            primary: 'bg-primary/15 text-primary',
          };
          return (
            <li key={key} className="flex gap-3 py-3 last:pb-1">
              <span className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full ${toneBg[vis.tone]}`} aria-hidden="true">
                <Icon size={13} />
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium leading-4 text-on-surface">{title}</p>
                <p className="truncate font-mono text-xs leading-4 text-on-surface-variant" title={a.target ?? undefined}>
                  {a.target ?? a.message ?? '—'}
                </p>
                {signal ? (
                  <span className="mt-1.5 inline-flex">
                    <Badge tone={signal.tone}>{signal.text}</Badge>
                  </span>
                ) : (
                  <span className="mt-1.5 inline-flex">
                    <Badge tone="primary">No threat signal</Badge>
                  </span>
                )}
                <p className="mt-1 font-mono text-[11px] uppercase tracking-wide text-on-surface-variant/60">
                  {formatRelative(a.created_at)}
                </p>
              </div>
            </li>
          );
        })}
      </ol>
      {hasMore && (
        <p className="mt-3 text-center text-xs text-on-surface-variant">
          Showing {maxItems} of {activities.length} · <Link to="/port-scanner" className="font-semibold text-primary hover:underline">View all</Link> to see full history
        </p>
      )}
    </Card>
  );
}

// Compact inline variant for embed without Card chrome (not used by dashboard but reusable)
export function SecurityActivityItem({ activity }: { activity: DashboardActivity }) {
  const vis = getVisual(activity);
  const Icon = vis.icon;
  const signal = getSignalLine(activity);
  return (
    <div className="flex gap-3 py-2">
      <span className="grid h-7 w-7 place-items-center rounded-full bg-surface-low border text-on-surface-variant" aria-hidden="true">
        <Icon size={13} />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">{getTitle(activity)}</p>
        <p className="font-mono text-xs text-on-surface-variant truncate">{activity.target ?? '—'}</p>
        {signal && <Badge tone={signal.tone}>{signal.text}</Badge>}
        <p className="font-mono text-[11px] uppercase text-on-surface-variant/60">{formatRelative(activity.created_at)}</p>
      </div>
    </div>
  );
}
