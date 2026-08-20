import { useState, FormEvent, useEffect } from 'react';
import {
  Play,
  Loader2,
  AlertCircle,
  RefreshCw,
  CheckCircle,
  FileText,
  Activity,
  MinusCircle,
  AlertOctagon,
  Network,
  BarChart3,
  Globe,
  ShieldCheck,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import { useSlowRequest } from '../hooks/useSlowRequest';
import { SlowRequestNotice } from '../components/SlowRequestNotice';
import type { LogAnalysisResult } from '../types';

const MAX_CONTENT_LENGTH = 500_000;

const LOG_FORMATS = [
  { value: 'auto', label: 'Auto' },
  { value: 'apache_combined', label: 'Apache Combined' },
] as const;

type SeverityTone = 'success' | 'warning' | 'danger' | 'primary';

const severityTone = (severity: LogAnalysisResult['severity']): SeverityTone => {
  switch (severity) {
    case 'high':
      return 'danger';
    case 'medium':
      return 'warning';
    case 'low':
      return 'success';
    default:
      return 'primary';
  }
};

const anomalySeverityTone = (severity: LogAnalysisResult['anomalies'][number]['severity']): SeverityTone => {
  switch (severity) {
    case 'High':
      return 'danger';
    case 'Medium':
      return 'warning';
    case 'Low':
      return 'primary';
    default:
      return 'primary';
  }
};

const statusCodeTone = (code: string): SeverityTone => {
  const value = Number(code);
  if (value >= 500) return 'danger';
  if (value >= 400) return 'warning';
  if (value >= 200 && value < 300) return 'success';
  return 'primary';
};

const presentSeverity = (severity: LogAnalysisResult['severity']): string =>
  severity.charAt(0).toUpperCase() + severity.slice(1);

function getApiErrorMessage(err: ApiClientError): string {
  if (err.status === 413) {
    return 'The log content is too large. Please reduce it to 500,000 characters or fewer.';
  }
  if (err.status === 401) {
    return 'You are not signed in. Please sign in and try again.';
  }
  if (err.status === 503) {
    return 'The log analysis service is temporarily unavailable. Please try again later.';
  }
  if (err.status === 0) {
    return 'Network request failed. Check your connection and try again.';
  }
  return err.message || 'Log analysis failed. Please try again.';
}

interface StatTileProps {
  readonly icon: LucideIcon;
  readonly label: string;
  readonly value: number;
}

function StatTile({ icon: Icon, label, value }: StatTileProps) {
  return (
    <div className="rounded border bg-surface-low p-4">
      <span className="grid h-9 w-9 place-items-center rounded bg-primary/10 text-primary">
        <Icon size={16} />
      </span>
      <p className="mt-3 font-display text-2xl font-bold text-on-surface">{value.toLocaleString()}</p>
      <p className="mt-1 text-xs text-on-surface-variant">{label}</p>
    </div>
  );
}

export function LogAnalyzerPage() {
  const [content, setContent] = useState('');
  const [logFormat, setLogFormat] = useState<string>('auto');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<LogAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { run, isSlow, elapsedSeconds } = useSlowRequest();

  useEffect(() => {
    return () => {
      setContent('');
      setResult(null);
      setError(null);
    };
  }, []);

  const handleAnalyze = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isAnalyzing) return;

    if (!content.trim()) {
      setError('Please paste some log content before analyzing.');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const analysis = await run(() => apiClient.post<LogAnalysisResult>('/logs/analyze', {
        content,
        log_format: logFormat,
      }));
      setResult(analysis);
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(getApiErrorMessage(err));
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setContent('');
    setLogFormat('auto');
    setResult(null);
    setError(null);
    setIsAnalyzing(false);
  };

  const statusCodeEntries = result
    ? Object.entries(result.stats.status_code_counts).sort((a, b) => Number(a[0]) - Number(b[0]))
    : [];

  return (
    <>
      <PageHeader
        eyebrow="Security telemetry"
        title="Log Analyzer"
        description="Paste server access or application logs to identify anomalous activity, authentication failures, and suspicious request patterns."
        actions={<Button variant="secondary" disabled={isAnalyzing}><RefreshCw size={16} /> History</Button>}
      />
      <div className="grid gap-5 xl:grid-cols-[1fr_0.9fr]">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Run analysis</p>
          <form onSubmit={handleAnalyze} className="mt-6 grid gap-4">
            <label className="grid gap-2 text-sm font-medium">
              <span>Log format</span>
              <select
                value={logFormat}
                onChange={(e) => setLogFormat(e.target.value)}
                disabled={isAnalyzing}
                aria-label="Log format"
                className="h-11 rounded border bg-surface-low px-3 text-on-surface focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              >
                {LOG_FORMATS.map((format) => (
                  <option key={format.value} value={format.value}>{format.label}</option>
                ))}
              </select>
            </label>

            <label className="grid gap-2 text-sm font-medium">
              <span>Log content</span>
              <textarea
                rows={12}
                value={content}
                onChange={(e) => {
                  setContent(e.target.value);
                  setError(null);
                }}
                disabled={isAnalyzing}
                maxLength={MAX_CONTENT_LENGTH}
                aria-label="Log content"
                placeholder={'Paste Apache-style access or application logs here, one event per line.\nExample:\n127.0.0.1 - - [17/Aug/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'}
                className="resize-none rounded border bg-surface-low p-3 font-mono text-sm placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
            </label>
            <p className="text-right text-xs text-on-surface-variant">
              {content.length.toLocaleString()} / {MAX_CONTENT_LENGTH.toLocaleString()} characters
            </p>

            <Button type="submit" disabled={isAnalyzing} className="w-full">
              {isAnalyzing ? (
                <>
                  <Loader2 size={16} className="animate-spin mr-2" /> Analyzing logs...
                </>
              ) : (
                <>
                  <Play size={16} className="mr-2" /> Analyze Logs
                </>
              )}
            </Button>

            {isAnalyzing && isSlow && (
              <SlowRequestNotice elapsedSeconds={elapsedSeconds} />
            )}

            {error && (
              <div className="flex items-center gap-2 text-sm text-destructive bg-destructive/10 p-3 rounded border">
                <AlertCircle size={16} /> {error}
              </div>
            )}

            <p className="text-xs leading-5 text-on-surface-variant">
              Log content is sent only to the analysis endpoint and processed in memory. Raw logs are never stored or retained.
            </p>
          </form>
        </Card>

        <Card className="p-5">
          {result ? (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Threat score</p>
                  <p className="mt-3 font-display text-4xl font-bold text-on-surface">{result.threat_score} / 100</p>
                  <p className="mt-2 text-sm leading-6 text-on-surface-variant">{result.summary}</p>
                </div>
                <Badge tone={severityTone(result.severity)}>{presentSeverity(result.severity)}</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Assessment summary</p>
                <p className="text-sm leading-6 text-on-surface-variant">
                  <code className="font-mono">{result.anomalies_detected}</code> anomaly(ies) across{' '}
                  <code className="font-mono">{result.stats.unique_ips}</code> unique source(s)
                </p>
                <p className="mt-2 font-mono text-[11px] uppercase tracking-wide text-on-surface-variant/60">{result.analyzer}</p>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Threat score</p>
                  <p className="mt-3 font-display text-3xl font-bold text-on-surface-variant/40">—</p>
                </div>
                <Badge tone="primary">Ready</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Assessment summary</p>
                <p className="text-sm leading-6 text-on-surface-variant">Paste log content and start an analysis to see results.</p>
              </div>
            </>
          )}
        </Card>
      </div>

      {result && (
        <>
          <Card className="mt-5">
            <div className="border-b px-5 py-4">
              <p className="font-display font-semibold flex items-center gap-2">
                <BarChart3 size={18} className="text-primary" /> Statistics
              </p>
            </div>
            <div className="grid gap-4 p-5 sm:grid-cols-2 lg:grid-cols-5">
              <StatTile icon={FileText} label="Total lines" value={result.total_lines} />
              <StatTile icon={Activity} label="Parsed events" value={result.parsed_lines} />
              <StatTile icon={MinusCircle} label="Skipped lines" value={result.skipped_lines} />
              <StatTile icon={AlertOctagon} label="Anomalies detected" value={result.anomalies_detected} />
              <StatTile icon={Network} label="Unique IPs" value={result.stats.unique_ips} />
            </div>
          </Card>

          <div className="mt-5 grid gap-5 lg:grid-cols-2">
            <Card>
              <div className="border-b px-5 py-4">
                <p className="font-display font-semibold flex items-center gap-2">
                  <ShieldCheck size={18} className="text-primary" /> HTTP status codes
                </p>
              </div>
              <div className="p-5">
                {statusCodeEntries.length === 0 ? (
                  <p className="text-sm text-on-surface-variant">No HTTP status codes were parsed from the log content.</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {statusCodeEntries.map(([code, count]) => (
                      <span key={code} className="inline-flex items-center gap-2 rounded border bg-surface-low px-3 py-2">
                        <Badge tone={statusCodeTone(code)}>{code}</Badge>
                        <span className="font-mono text-sm text-on-surface-variant">{count.toLocaleString()}</span>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </Card>

            <Card>
              <div className="border-b px-5 py-4">
                <p className="font-display font-semibold flex items-center gap-2">
                  <Globe size={18} className="text-primary" /> Top sources
                </p>
              </div>
              <div className="p-5">
                {result.stats.top_sources.length === 0 ? (
                  <p className="text-sm text-on-surface-variant">No parsed request sources to display.</p>
                ) : (
                  <div className="space-y-2">
                    {result.stats.top_sources.map(([ip, count]) => (
                      <div key={ip} className="flex items-center justify-between gap-3 rounded border bg-surface-low px-4 py-3">
                        <code className="font-mono text-sm text-on-surface">{ip}</code>
                        <Badge tone="primary">{count.toLocaleString()} event{count === 1 ? '' : 's'}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Card>
          </div>

          <Card className="mt-5">
            <div className="border-b px-5 py-4">
              <p className="font-display font-semibold flex items-center gap-2">
                <AlertOctagon size={18} className="text-primary" /> Findings
              </p>
            </div>
            {result.anomalies_detected === 0 ? (
              <div className="flex items-center gap-3 px-5 py-4">
                <CheckCircle size={18} className="text-success" />
                <p className="text-sm text-on-surface-variant">No anomalies detected.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[520px] text-left text-sm">
                  <thead className="border-y bg-surface-low font-mono text-[11px] uppercase tracking-wider text-on-surface-variant">
                    <tr>
                      <th className="px-4 py-3 font-medium">Line</th>
                      <th className="px-4 py-3 font-medium">Finding</th>
                      <th className="px-4 py-3 font-medium">Severity</th>
                      <th className="px-4 py-3 font-medium">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.anomalies.map((anomaly, index) => (
                      <tr key={index} className="border-b last:border-0 hover:bg-surface-high/40">
                        <td className="px-4 py-3 font-medium text-on-surface">{anomaly.line_number ?? 'N/A'}</td>
                        <td className="px-4 py-3 text-on-surface">{anomaly.type}</td>
                        <td className="px-4 py-3">
                          <Badge tone={anomalySeverityTone(anomaly.severity)}>{anomaly.severity}</Badge>
                        </td>
                        <td className="px-4 py-3 text-on-surface-variant">{anomaly.evidence}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <div className="mt-5 flex justify-end">
            <Button variant="secondary" onClick={handleReset}>
              <RefreshCw size={16} className="mr-2" /> New analysis
            </Button>
          </div>
        </>
      )}
    </>
  );
}
