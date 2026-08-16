import { useEffect, useState } from 'react';
import { ArrowUpRight, Plus, RefreshCw, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Badge, Button, Card, DataTable } from '../components/ui';
import { NewScanModal } from '../components/NewScanModal';
import { PageHeader } from '../components/PageHeader';
import { apiClient } from '../services/apiClient';
import type { DashboardData, DashboardMetric } from '../types';

export interface DashboardPageProps {
  readonly compact?: boolean;
}

function formatTimestamp(isoString: string | null): string {
  if (!isoString) return 'Unknown';
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins} min ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function getToneClass(tone: DashboardMetric['tone']): 'success' | 'primary' | 'danger' | 'warning' {
  return tone;
}

function getMaxTrendValue(values: readonly number[]): number {
  const max = Math.max(...values, 1);
  return Math.ceil(max / 10) * 10 || 100;
}

interface NewScanButtonProps { readonly onClick: () => void; }
function NewScanButton({ onClick }: NewScanButtonProps) {
  return <Button onClick={onClick}><Plus size={17} /> New scan</Button>;
}

export function DashboardPage({ compact = false }: DashboardPageProps) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isNewScanOpen, setIsNewScanOpen] = useState(false);

  const fetchDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.get<DashboardData>('/dashboard');
      setData(response);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load dashboard';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  const metrics = data?.metrics;
  const recentScans = data?.recent_scans ?? [];
  const activity = data?.activity ?? [];
  const trend = data?.trend;
  const maxTrend = trend ? getMaxTrendValue(trend.values) : 100;

  if (loading) {
    return (
      <>
        <PageHeader
          eyebrow="Security overview"
          title="Your security posture"
          description="Monitor assessment activity and focus your response on the signals that matter."
          actions={<NewScanButton onClick={() => setIsNewScanOpen(true)} />}
        />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {['Security score', 'Scans completed', 'Threats detected', 'Assets monitored'].map((label) => (
            <Card key={label} className="p-5 animate-pulse">
              <p className="text-sm text-on-surface-variant">{label}</p>
              <div className="mt-3 flex items-end justify-between">
                <div className="h-10 w-24 bg-surface-high rounded" />
                <div className="h-6 w-20 bg-surface-high rounded" />
              </div>
              <p className="mt-3 text-xs text-on-surface-variant">
                <span className="h-4 w-32 bg-surface-high rounded inline-block" />
              </p>
            </Card>
          ))}
        </div>
        <div className="mt-5 grid gap-5 xl:grid-cols-[1.6fr_1fr]">
          <Card className="animate-pulse">
            <div className="flex items-center justify-between border-b px-5 py-4">
              <div>
                <p className="font-display font-semibold">Security activity</p>
                <p className="mt-1 text-xs text-on-surface-variant">Threat trend across recent scans</p>
              </div>
              <div className="h-6 w-20 bg-surface-high rounded" />
            </div>
            <div className="h-64 p-5">
              <div className="flex h-full items-end gap-2">
                {Array.from({ length: 12 }).map((_, index) => (
                  <div key={index} className="group flex flex-1 flex-col justify-end">
                    <div className="h-20 w-full bg-surface-high rounded-t" />
                    <span className="mt-2 text-center font-mono text-[10px] text-on-surface-variant">
                      {index + 1}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </Card>
          <Card className="p-5 animate-pulse">
            <div className="flex items-center gap-2">
              <div className="h-5 w-5 bg-surface-high rounded" />
              <div className="h-6 w-40 bg-surface-high rounded" />
            </div>
            <div className="mt-5 space-y-5">
              {Array.from({ length: 3 }).map((_, index) => (
                <div key={index} className="flex gap-3">
                  <div className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-surface-high" />
                  <div className="h-5 w-64 bg-surface-high rounded" />
                </div>
              ))}
            </div>
          </Card>
        </div>
        <Card className="mt-5 animate-pulse">
          <div className="flex items-center justify-between border-b px-5 py-4">
            <div>
              <p className="font-display font-semibold">Recent assessments</p>
              <p className="mt-1 text-xs text-on-surface-variant">Latest scan results</p>
            </div>
            <div className="h-6 w-32 bg-surface-high rounded" />
          </div>
          <div className="p-5">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[520px] text-left text-sm">
                <thead className="border-y bg-surface-low font-mono text-[11px] uppercase tracking-wider text-on-surface-variant">
                  <tr>
                    {['Target', 'Type', 'Risk', 'Completed'].map((header) => (
                      <th key={header} className="px-4 py-3 font-medium">
                        <div className="h-4 w-24 bg-surface-high rounded" />
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {Array.from({ length: 4 }).map((_, rowIndex) => (
                    <tr key={rowIndex} className="border-b last:border-0">
                      {Array.from({ length: 4 }).map((_, colIndex) => (
                        <td key={colIndex} className="px-4 py-3">
                          <div className="h-4 w-24 bg-surface-high rounded" />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </Card>
        {isNewScanOpen && <NewScanModal onClose={() => setIsNewScanOpen(false)} />}
        {compact && <p className="hidden">compact</p>}
      </>
    );
  }

  if (error) {
    return (
      <>
        <PageHeader
          eyebrow="Security overview"
          title="Your security posture"
          description="Monitor assessment activity and focus your response on the signals that matter."
          actions={<NewScanButton onClick={() => setIsNewScanOpen(true)} />}
        />
        <Card className="p-8 text-center">
          <div className="text-danger mb-4" role="alert">
            <p className="font-display font-semibold">Unable to load dashboard</p>
            <p className="mt-2 text-on-surface-variant">{error}</p>
          </div>
          <Button variant="primary" onClick={fetchDashboard}>
            <RefreshCw className="mr-2" size={17} />
            Retry
          </Button>
        </Card>
      </>
    );
  }

  if (!data) {
    return (
      <>
        <PageHeader
          eyebrow="Security overview"
          title="Your security posture"
          description="Monitor assessment activity and focus your response on the signals that matter."
          actions={<NewScanButton onClick={() => setIsNewScanOpen(true)} />}
        />
        <Card className="p-8 text-center">
          <p className="text-on-surface-variant">No dashboard data available</p>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        eyebrow="Security overview"
        title="Your security posture"
        description="Monitor assessment activity and focus your response on the signals that matter."
        actions={<NewScanButton onClick={() => setIsNewScanOpen(true)} />}
      />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          { label: 'Security score', metric: metrics?.security_score },
          { label: 'Scans completed', metric: metrics?.scans_completed },
          { label: 'Threats detected', metric: metrics?.threats_detected },
          { label: 'Assets monitored', metric: metrics?.assets_monitored },
        ].map(({ label, metric }) => (
          <Card key={label} className="p-5">
            <p className="text-sm text-on-surface-variant">{label}</p>
            <div className="mt-3 flex items-end justify-between">
              <p className="font-display text-3xl font-bold">
                {metric?.value ?? 0}
              </p>
              <Badge tone={getToneClass(metric?.tone ?? 'primary')}>
                {metric?.tone ?? 'primary'}
              </Badge>
            </div>
            <p className="mt-3 text-xs text-on-surface-variant">
              {metric?.detail ?? 'No data'}
            </p>
          </Card>
        ))}
      </div>
      <div className="mt-5 grid gap-5 xl:grid-cols-[1.6fr_1fr]">
        <Card>
          <div className="flex items-center justify-between border-b px-5 py-4">
            <div>
              <p className="font-display font-semibold">Security activity</p>
              <p className="mt-1 text-xs text-on-surface-variant">
                Threat trend across recent scans
              </p>
            </div>
            <Badge tone="success">Protected</Badge>
          </div>
          <div className="h-64 p-5">
            {trend && trend.values.length > 0 ? (
              <div className="flex h-full items-end gap-2">
                {trend.values.map((value, index) => (
                  <div
                    key={index}
                    className="group flex flex-1 flex-col justify-end"
                  >
                    <div
                      className="rounded-t bg-primary/70 transition group-hover:bg-primary"
                      style={{
                        height: `${(value / maxTrend) * 100}%`,
                        minHeight: value > 0 ? '4px' : '0',
                      }}
                    />
                    <span className="mt-2 text-center font-mono text-[10px] text-on-surface-variant">
                      {trend.labels[index]?.slice(5) ?? index + 1}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-full flex items-center justify-center text-on-surface-variant">
                No trend data available
              </div>
            )}
          </div>
        </Card>
        <Card className="p-5">
          <div className="flex items-center gap-2">
            <ShieldCheck className="text-success" size={20} />
            <p className="font-display font-semibold">Priority activity</p>
          </div>
          <div className="mt-5 space-y-5">
            {activity.length > 0 ? (
              activity.map((item, index) => (
                <div key={`${item.message}-${index}`} className="flex gap-3">
                  <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-primary" />
                  <p className="text-sm leading-5 text-on-surface-variant">
                    {item.message}
                    <span className="mt-1 block font-mono text-[10px] uppercase text-on-surface-variant/60">
                      {formatTimestamp(item.created_at)}
                    </span>
                  </p>
                </div>
              ))
            ) : (
              <p className="text-center text-on-surface-variant py-8">
                No recent activity
              </p>
            )}
          </div>
        </Card>
      </div>
      <Card className="mt-5">
        <div className="flex items-center justify-between border-b px-5 py-4">
          <div>
            <p className="font-display font-semibold">Recent assessments</p>
            <p className="mt-1 text-xs text-on-surface-variant">
              Latest scan results
            </p>
          </div>
          <Link className="inline-flex items-center gap-1 text-sm font-semibold text-primary" to="/reports">
            View reports <ArrowUpRight size={15} />
          </Link>
        </div>
        {recentScans.length > 0 ? (
          <DataTable
            headers={['Target', 'Type', 'Risk', 'Completed']}
            rows={recentScans.map((scan) => [
              scan.target,
              scan.type,
              scan.risk,
              formatTimestamp(scan.completed_at),
            ])}
          />
        ) : (
          <div className="p-8 text-center text-on-surface-variant">
            No recent scans
          </div>
        )}
      </Card>
      {isNewScanOpen && <NewScanModal onClose={() => setIsNewScanOpen(false)} />}
        {compact && <p className="hidden">compact</p>}
    </>
  );
}