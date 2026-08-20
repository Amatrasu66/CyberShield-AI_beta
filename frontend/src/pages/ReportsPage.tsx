import { FormEvent, useCallback, useEffect, useState } from 'react';
import { AlertCircle, CheckCircle, FileSearch, FileText, Loader2, Plus, RefreshCw } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card, TextInput } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import { useSlowRequest } from '../hooks/useSlowRequest';
import { SlowRequestNotice } from '../components/SlowRequestNotice';
import type { Report, ReportGenerateRequest } from '../types';

const TITLE_MAX_LENGTH = 200;
const TITLE_INPUT_ID = 'report-title-input';

function getApiErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiClientError) {
    if (err.status === 401) {
      return 'Your session has expired. Please sign in again.';
    }
    if (err.status === 503) {
      return 'The reports service is temporarily unavailable. Please try again later.';
    }
    if (err.status === 400) {
      return 'Invalid report request. Please check your input and try again.';
    }
    if (err.status === 0) {
      return 'Unable to connect to the backend. Check your connection and try again.';
    }
    return err.message || fallback;
  }
  return fallback;
}

function formatReportDate(isoString: string): string {
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return 'Unknown date';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
  if (diffHours < 24) return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function ReportCardSkeleton() {
  return (
    <Card className="animate-pulse p-5">
      <div className="flex items-center justify-between">
        <div className="h-5 w-24 rounded bg-surface-bright/30" />
        <div className="h-4 w-20 rounded bg-surface-bright/20" />
      </div>
      <div className="mt-5 h-5 w-3/4 rounded bg-surface-bright/30" />
      <div className="mt-3 h-4 w-full rounded bg-surface-bright/20" />
      <div className="mt-2 h-4 w-2/3 rounded bg-surface-bright/20" />
      <div className="mt-6 h-10 w-full rounded bg-surface-bright/20" />
    </Card>
  );
}

export function ReportsPage() {
  const [reports, setReports] = useState<Report[] | null>(null);
  const [title, setTitle] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [openingId, setOpeningId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generationError, setGenerationError] = useState<string | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const { run, isSlow, elapsedSeconds } = useSlowRequest();

  const fetchReports = useCallback(async (mode: 'initial' | 'refresh') => {
    if (mode === 'initial') {
      setIsLoading(true);
    } else {
      setIsRefreshing(true);
    }
    setError(null);
    try {
      const data = await run(() => apiClient.get<Report[]>('/reports'));
      setReports(data);
    } catch (err) {
      setError(getApiErrorMessage(err, 'Unable to load reports. Please try again.'));
    } finally {
      if (mode === 'initial') {
        setIsLoading(false);
      } else {
        setIsRefreshing(false);
      }
    }
  }, [run]);

  useEffect(() => {
    fetchReports('initial');
  }, [fetchReports]);

  const handleGenerate = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isGenerating) return;

    setIsGenerating(true);
    setGenerationError(null);
    setSuccessMessage(null);

    const trimmed = title.trim();
    const body: ReportGenerateRequest = trimmed.length > 0 ? { title: trimmed } : {};

    try {
      const created = await run(() => apiClient.post<Report>('/reports/generate', body));
      setReports((prev) => [created, ...(prev ?? [])]);
      setTitle('');
      setSuccessMessage('Your security report was generated successfully.');
    } catch (err) {
      setGenerationError(getApiErrorMessage(err, 'Unable to generate report. Please try again.'));
    } finally {
      setIsGenerating(false);
    }
  };

  const handleOpenReport = async (reportId: string) => {
    if (openingId !== null) return;

    setOpeningId(reportId);
    setOpenError(null);

    try {
      const fresh = await run(() => apiClient.get<Report[]>('/reports'));
      setReports(fresh);
      const found = fresh.find((report) => report.id === reportId);
      if (!found || !found.signed_url) {
        setOpenError('The report link may have expired. Refresh the reports and try again.');
        return;
      }
      window.open(found.signed_url, '_blank', 'noopener,noreferrer');
    } catch (err) {
      setOpenError('The report link may have expired. Refresh the reports and try again.');
    } finally {
      setOpeningId(null);
    }
  };

  const focusGenerate = () => {
    const input = document.getElementById(TITLE_INPUT_ID);
    input?.focus();
    input?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  };

  const hasReports = reports !== null && reports.length > 0;

  return (
    <>
      <PageHeader
        eyebrow="Audit evidence"
        title="Security Reports"
        description="Review and download PDF security reports generated from your latest scan results."
        actions={
          <>
            <Button
              variant="secondary"
              disabled={isLoading || isRefreshing || isGenerating}
              onClick={() => fetchReports('refresh')}
            >
              {isRefreshing ? <Loader2 size={16} className="animate-spin" /> : <RefreshCw size={16} />}
              Refresh
            </Button>
            <Button disabled={isGenerating} onClick={focusGenerate}>
              <Plus size={16} /> Generate Report
            </Button>
          </>
        }
      />

      {isSlow && !isLoading && !isGenerating && (
        <div className="mb-5">
          <SlowRequestNotice elapsedSeconds={elapsedSeconds} />
        </div>
      )}

      <Card className="p-5">
        <p className="font-display text-lg font-semibold">Generate report</p>
        <form onSubmit={handleGenerate} className="mt-5 grid gap-4 md:grid-cols-[1fr_auto] md:items-end">
          <TextInput
            id={TITLE_INPUT_ID}
            label="Report title (optional)"
            placeholder="Security Audit Report"
            value={title}
            onChange={(e) => {
              setTitle(e.target.value);
              setGenerationError(null);
            }}
            disabled={isGenerating}
            maxLength={TITLE_MAX_LENGTH}
          />
          <Button type="submit" disabled={isGenerating} className="md:w-auto">
            {isGenerating ? (
              <>
                <Loader2 size={16} className="animate-spin" /> Generating…
              </>
            ) : (
              <>
                <FileText size={16} /> Generate Report
              </>
            )}
          </Button>
        </form>

        {isGenerating && (
          isSlow ? (
            <div className="mt-4">
              <SlowRequestNotice elapsedSeconds={elapsedSeconds} />
            </div>
          ) : (
            <div className="mt-4 flex items-start gap-2 rounded border bg-surface-low p-3 text-sm text-on-surface-variant">
              <Loader2 size={16} className="mt-0.5 shrink-0 animate-spin text-primary" />
              <p>
                Generating security report... Your latest scan results are being aggregated and compiled
                into a PDF. This may take a moment.
              </p>
            </div>
          )
        )}

        {successMessage && (
          <div className="mt-4 flex items-center gap-2 rounded border border-success/20 bg-success/10 p-3 text-sm text-success">
            <CheckCircle size={16} className="shrink-0" /> {successMessage}
          </div>
        )}

        {generationError && (
          <div className="mt-4 flex items-center gap-2 rounded border bg-destructive/10 p-3 text-sm text-destructive">
            <AlertCircle size={16} className="shrink-0" /> {generationError}
          </div>
        )}
      </Card>

      {isLoading ? (
        <>
          {isSlow && <div className="mt-5"><SlowRequestNotice elapsedSeconds={elapsedSeconds} /></div>}
          <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 3 }).map((_, index) => (
              <ReportCardSkeleton key={index} />
            ))}
          </div>
        </>
      ) : error && !hasReports ? (
        <Card className="mt-5 p-8 text-center">
          <div className="text-danger" role="alert">
            <p className="font-display font-semibold">Unable to load reports</p>
            <p className="mt-2 text-on-surface-variant">{error}</p>
          </div>
          <Button className="mt-5" onClick={() => fetchReports('initial')}>
            <RefreshCw className="mr-2" size={16} /> Retry
          </Button>
        </Card>
      ) : hasReports ? (
        <>
          {error && (
            <div className="mt-5 flex items-center gap-2 rounded border bg-destructive/10 p-3 text-sm text-destructive">
              <AlertCircle size={16} className="shrink-0" /> {error}
            </div>
          )}
          {openError && (
            <div className="mt-5 flex items-center gap-2 rounded border bg-destructive/10 p-3 text-sm text-destructive">
              <AlertCircle size={16} className="shrink-0" /> {openError}
            </div>
          )}
          <div className="mt-5 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            {reports.map((report) => (
              <Card key={report.id} className="flex flex-col p-5">
                <div className="flex items-center justify-between gap-3">
                  <Badge tone="primary">
                    <FileText size={12} className="mr-1" /> PDF Report
                  </Badge>
                  <span className="font-mono text-[11px] text-on-surface-variant">
                    {formatReportDate(report.created_at)}
                  </span>
                </div>
                <h2 className="mt-4 font-display text-lg font-semibold leading-snug">{report.title}</h2>
                {report.report_data?.summary && (
                  <p className="mt-2 line-clamp-2 text-sm leading-6 text-on-surface-variant">
                    {report.report_data.summary}
                  </p>
                )}
                <div className="mt-auto pt-5">
                  <Button
                    variant="secondary"
                    className="w-full"
                    disabled={openingId !== null}
                    onClick={() => handleOpenReport(report.id)}
                  >
                    {openingId === report.id ? (
                      <>
                        <Loader2 size={16} className="animate-spin" /> Opening…
                      </>
                    ) : (
                      <>
                        <FileText size={16} /> View Report
                      </>
                    )}
                  </Button>
                </div>
              </Card>
            ))}
          </div>
        </>
      ) : (
        <Card className="mt-5 flex flex-col items-center justify-center p-10 text-center">
          <span className="mb-4 grid h-14 w-14 place-items-center rounded-full bg-primary/10 text-primary">
            <FileSearch size={26} />
          </span>
          <h2 className="font-display text-lg font-semibold">No security reports yet.</h2>
          <p className="mt-2 max-w-sm text-sm text-on-surface-variant">
            Generate your first security report from your latest scan results.
          </p>
          <Button className="mt-5" onClick={focusGenerate}>
            <FileText size={16} /> Generate Report
          </Button>
        </Card>
      )}
    </>
  );
}
