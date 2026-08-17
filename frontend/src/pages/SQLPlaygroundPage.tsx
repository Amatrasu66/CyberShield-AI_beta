import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import {
  AlertCircle,
  Braces,
  CheckCircle,
  Info,
  Loader2,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
} from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card, DataTable } from '../components/ui';
import { LoadingStates } from '../components/LoadingStates';
import { apiClient, ApiClientError } from '../services/apiClient';
import type { SqlRunRequest, SqlRunResult, SqlScenario, SqlResultSet } from '../types';

const PAYLOAD_MAX_LENGTH = 2048;

function friendlyError(err: unknown): string {
  if (err instanceof ApiClientError) {
    switch (err.status) {
      case 401:
        return 'Your session has expired. Please sign in again and retry.';
      case 413:
        return 'The submitted payload is too large. Please shorten it and try again.';
      case 400:
        return err.message || 'The request was rejected. Please check the payload and try again.';
      case 500:
        return 'The lab encountered an internal error. Please try again shortly.';
      case 0:
        return 'Network request failed. Check your connection and try again.';
      default:
        return err.message || 'Something went wrong. Please try again.';
    }
  }
  return 'An unexpected error occurred. Please try again.';
}

function toTableRows(set: SqlResultSet): string[][] {
  return set.data.map((row) => row.map((cell) => (cell === null ? 'NULL' : String(cell))));
}

type OutcomeTone = 'danger' | 'warning' | 'success';

interface Outcome {
  readonly tone: OutcomeTone;
  readonly title: string;
  readonly detail: string;
}

function buildOutcome(result: SqlRunResult): Outcome {
  const vuln = result.vulnerable_result;
  const safe = result.safe_result;
  if (vuln.execution_status === 'rejected') {
    return {
      tone: 'warning',
      title: 'The vulnerable implementation rejected the payload',
      detail: `The payload was blocked (${vuln.rejection_reason ?? 'rejected by the sandbox'}). The parameterized query treated the same input as data and returned ${safe.rows} row(s).`,
    };
  }
  if (vuln.rows > 0 && safe.rows === 0) {
    return {
      tone: 'danger',
      title: 'Injection succeeded against the vulnerable implementation',
      detail: `The vulnerable path returned ${vuln.rows} row(s) influenced by the payload. The parameterized query rejected the payload as data and returned ${safe.rows} row(s).`,
    };
  }
  if (vuln.rows !== safe.rows) {
    return {
      tone: 'warning',
      title: 'Row counts differ between the two implementations',
      detail: `The vulnerable path returned ${vuln.rows} row(s); the parameterized path returned ${safe.rows} row(s).`,
    };
  }
  return {
    tone: 'success',
    title: 'Both implementations returned the same rows',
    detail: `The vulnerable path returned ${vuln.rows} row(s) and the parameterized path returned ${safe.rows} row(s). The payload did not change the outcome of either query.`,
  };
}

interface ResultPanelProps {
  readonly title: string;
  readonly intro: string;
  readonly badge: ReactNode;
  readonly query: string;
  readonly queryLabel: string;
  readonly resultSet: SqlResultSet;
}

function ResultPanel({ title, intro, badge, query, queryLabel, resultSet }: ResultPanelProps) {
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-display text-lg font-semibold">{title}</p>
          <p className="mt-1 text-sm leading-6 text-on-surface-variant">{intro}</p>
        </div>
        {badge}
      </div>

      <div className="mt-4">
        <p className="eyebrow mb-1">{queryLabel}</p>
        <pre className="whitespace-pre-wrap break-words rounded border bg-surface-low p-3 font-mono text-xs leading-5 text-on-surface">{query}</pre>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
        <div className="rounded border bg-surface-low p-3">
          <p className="eyebrow">Rows returned</p>
          <p className="mt-1 font-display text-xl font-bold">{resultSet.rows}</p>
        </div>
        <div className="rounded border bg-surface-low p-3">
          <p className="eyebrow">Columns</p>
          <p className="mt-1 font-mono text-sm text-on-surface">{resultSet.columns.length}</p>
        </div>
        <div className="rounded border bg-surface-low p-3">
          <p className="eyebrow">Status</p>
          <p className="mt-1 font-mono text-sm">{resultSet.execution_status === 'ok' ? 'Executed' : 'Rejected'}</p>
        </div>
      </div>

      {resultSet.execution_status === 'rejected' && (
        <div className="mt-4 rounded border border-danger/30 bg-danger/5 p-3 text-sm text-destructive">
          {resultSet.rejection_reason ?? 'The query was rejected by the sandbox.'}
        </div>
      )}

      {resultSet.execution_status === 'ok' && resultSet.columns.length > 0 && (
        <div className="mt-4">
          <p className="eyebrow mb-2">Returned data</p>
          {resultSet.data.length > 0 ? (
            <DataTable headers={resultSet.columns} rows={toTableRows(resultSet)} />
          ) : (
            <p className="text-sm text-on-surface-variant">No rows matched.</p>
          )}
        </div>
      )}
    </Card>
  );
}

function ExplanationSection({ title, text }: { readonly title: string; readonly text: string }) {
  return (
    <div className="py-3 first:pt-0 last:pb-0">
      <p className="text-sm font-semibold text-on-surface">{title}</p>
      <p className="mt-1 text-sm leading-6 text-on-surface-variant">{text}</p>
    </div>
  );
}

export function SQLPlaygroundPage() {
  const [scenarios, setScenarios] = useState<Record<string, SqlScenario> | null>(null);
  const [scenarioLoading, setScenarioLoading] = useState(true);
  const [scenarioError, setScenarioError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [payload, setPayload] = useState('');
  const [runState, setRunState] = useState<'idle' | 'running' | 'success' | 'error'>('idle');
  const [result, setResult] = useState<SqlRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadScenarios = useCallback(async () => {
    setScenarioLoading(true);
    setScenarioError(null);
    try {
      const data = await apiClient.get<Record<string, SqlScenario>>('/sql/scenarios');
      const entries = Object.entries(data ?? {});
      if (entries.length === 0) {
        setScenarioError('No lab scenarios are available right now.');
        setScenarios(null);
      } else {
        setScenarios(data);
        setSelectedId((prev) => (prev !== null && prev in data ? prev : entries[0][0]));
      }
    } catch (err) {
      setScenarioError(friendlyError(err));
      setScenarios(null);
    } finally {
      setScenarioLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadScenarios();
  }, [loadScenarios]);

  useEffect(() => {
    return () => {
      setPayload('');
      setResult(null);
      setError(null);
    };
  }, []);

  const scenarioEntries = useMemo(() => Object.entries(scenarios ?? {}), [scenarios]);
  const selected = selectedId !== null ? (scenarios?.[selectedId] ?? null) : null;

  const handleScenarioChange = (id: string) => {
    setSelectedId(id);
    setPayload('');
    setResult(null);
    setError(null);
    setRunState('idle');
  };

  const handleUseExample = () => {
    if (selected !== null) {
      setPayload(selected.example_payload);
      setError(null);
    }
  };

  const handleRun = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (runState === 'running' || selectedId === null) return;
    if (!payload.trim()) {
      setError('Enter an attack payload to test against the selected scenario.');
      return;
    }
    setRunState('running');
    setError(null);
    setResult(null);
    try {
      const requestBody: SqlRunRequest = { scenario: selectedId, payload };
      const runResult = await apiClient.post<SqlRunResult>('/sql/run', requestBody);
      if (runResult === undefined || runResult === null || typeof runResult !== 'object' || !('vulnerable_result' in runResult)) {
        setError('The lab returned an unexpected response. Please try again.');
        setRunState('error');
      } else {
        setResult(runResult);
        setRunState('success');
      }
    } catch (err) {
      setError(friendlyError(err));
      setRunState('error');
    }
  };

  const handleReset = () => {
    setPayload('');
    setResult(null);
    setError(null);
    setRunState('idle');
  };

  const outcome = result !== null ? buildOutcome(result) : null;
  const OutcomeIcon = outcome === null ? CheckCircle : outcome.tone === 'danger' ? XCircle : outcome.tone === 'warning' ? AlertCircle : CheckCircle;
  const canReset = payload !== '' || result !== null || error !== null;

  return (
    <>
      <PageHeader
        eyebrow="Security Lab"
        title="SQL Injection Playground"
        description="Explore how SQL injection works in an isolated demo database—and how parameterized queries stop it."
        actions={
          <Button variant="secondary" onClick={handleReset} disabled={runState === 'running' || !canReset}>
            <RotateCcw size={16} /> Reset playground
          </Button>
        }
      />

      <Card className="border-warning/40 bg-warning/5 p-5">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-0.5 shrink-0 text-warning" size={20} />
          <div>
            <p className="font-display font-semibold">Educational sandbox only</p>
            <ul className="mt-2 space-y-1.5 text-sm leading-6 text-on-surface-variant">
              <li>This is an isolated, in-memory demo database created fresh for each request.</li>
              <li>It does not access CyberShield production data.</li>
              <li>It does not access Supabase or any other external service.</li>
              <li>Nothing you enter here is persisted, logged, or stored.</li>
              <li>The database exists only for the current demonstration.</li>
            </ul>
          </div>
        </div>
      </Card>

      <Card className="mt-5 p-5">
        <p className="font-display text-lg font-semibold">Scenario &amp; payload</p>

        {scenarioLoading ? (
          <div className="mt-5" aria-busy="true" aria-label="Loading lab scenarios">
            <LoadingStates rows={2} />
          </div>
        ) : scenarioError !== null ? (
          <div className="mt-5 flex flex-col items-start gap-3 rounded border border-danger/30 bg-danger/5 p-4">
            <div className="flex items-center gap-2 text-sm text-destructive" role="alert">
              <AlertCircle size={16} /> {scenarioError}
            </div>
            <Button variant="secondary" onClick={() => void loadScenarios()}>
              <RefreshCw size={16} /> Retry
            </Button>
          </div>
        ) : selected !== null ? (
          <form onSubmit={handleRun} className="mt-5 grid gap-5" aria-busy={runState === 'running'}>
            <label className="grid gap-2 text-sm font-medium text-on-surface">
              <span>Scenario</span>
              <select
                value={selectedId ?? scenarioEntries[0]?.[0] ?? ''}
                onChange={(e) => handleScenarioChange(e.target.value)}
                disabled={runState === 'running'}
                aria-label="Choose an SQL injection scenario"
                className="h-11 rounded border bg-surface px-3 text-on-surface focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              >
                {scenarioEntries.map(([id, scenario]) => (
                  <option value={id} key={id}>
                    {scenario.name}
                  </option>
                ))}
              </select>
            </label>

            <div>
              <p className="font-display font-semibold">{selected.name}</p>
              <p className="mt-1 text-sm leading-6 text-on-surface-variant">{selected.description}</p>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 rounded border bg-surface-low p-3">
              <div className="min-w-0">
                <p className="eyebrow mb-1">Example payload</p>
                <code className="block break-all font-mono text-sm text-on-surface">{selected.example_payload}</code>
              </div>
              <Button type="button" variant="secondary" onClick={handleUseExample} disabled={runState === 'running'}>
                <Braces size={16} /> Use example
              </Button>
            </div>

            <label className="grid gap-2 text-sm font-medium text-on-surface">
              <span>Attack payload</span>
              <input
                type="text"
                value={payload}
                onChange={(e) => {
                  setPayload(e.target.value);
                  setError(null);
                }}
                maxLength={PAYLOAD_MAX_LENGTH}
                disabled={runState === 'running'}
                placeholder={selected.example_payload}
                aria-label="Attack payload to test against the selected scenario"
                aria-describedby="sql-payload-help sql-payload-count"
                className="h-11 rounded border bg-surface-low px-3 font-mono text-sm placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
              <span id="sql-payload-help" className="text-xs leading-5 text-on-surface-variant">
                Enter a payload to test against the selected scenario. The value is inserted into the educational demo only.
              </span>
              <span id="sql-payload-count" className="text-right font-mono text-xs text-on-surface-variant" aria-live="polite">
                {payload.length} / {PAYLOAD_MAX_LENGTH}
              </span>
            </label>

            <div>
              <Button type="submit" disabled={runState === 'running'} className="w-full sm:w-auto">
                {runState === 'running' ? (
                  <>
                    <Loader2 size={16} className="mr-2 animate-spin" /> Running isolated demo…
                  </>
                ) : (
                  <>
                    <Play size={16} className="mr-2" /> Run injection demo
                  </>
                )}
              </Button>
              {runState === 'running' && (
                <p className="sr-only" role="status">
                  Running the isolated demo. Please wait.
                </p>
              )}
            </div>

            {error !== null && (
              <div role="alert" className="flex items-start gap-2 rounded border border-danger/30 bg-danger/5 p-3 text-sm text-destructive">
                <AlertCircle size={16} className="mt-0.5 shrink-0" />
                <p>{error}</p>
              </div>
            )}
          </form>
        ) : null}
      </Card>

      {result !== null && outcome !== null && (
        <>
          <Card className="mt-5 p-5">
            <div className="flex items-start gap-3">
              <OutcomeIcon
                size={20}
                className={`mt-0.5 shrink-0 ${outcome.tone === 'danger' ? 'text-danger' : outcome.tone === 'warning' ? 'text-warning' : 'text-success'}`}
              />
              <div>
                <p className="font-display text-lg font-semibold">{outcome.title}</p>
                <p className="mt-1 text-sm leading-6 text-on-surface-variant">{outcome.detail}</p>
              </div>
            </div>
          </Card>

          <div className="mt-5 grid gap-5 lg:grid-cols-2">
            <ResultPanel
              title="Vulnerable implementation"
              intro="The payload is interpolated into a SQL statement."
              query={result.vulnerable_query}
              queryLabel="Executed query (interpolated)"
              resultSet={result.vulnerable_result}
              badge={
                <Badge tone="danger">
                  <XCircle size={12} className="mr-1" /> Vulnerable
                </Badge>
              }
            />
            <ResultPanel
              title="Parameterized implementation"
              intro="The payload is treated as data rather than executable SQL."
              query={result.safe_query}
              queryLabel="Executed query (bound parameters)"
              resultSet={result.safe_result}
              badge={
                <Badge tone="success">
                  <ShieldCheck size={12} className="mr-1" /> Secure
                </Badge>
              }
            />
          </div>
        </>
      )}

      {selected !== null && (
        <Card className="mt-5">
          <div className="border-b px-5 py-4">
            <p className="font-display font-semibold flex items-center gap-2">
              <Terminal size={18} className="text-primary" /> Vulnerable vs parameterized SQL
            </p>
          </div>
          <div className="grid gap-5 p-5 lg:grid-cols-2">
            <div>
              <p className="eyebrow mb-2 flex items-center gap-2">
                <XCircle size={12} className="text-danger" /> Vulnerable · string concatenation / interpolation
              </p>
              <pre className="whitespace-pre-wrap break-words rounded border bg-surface-low p-3 font-mono text-xs leading-5 text-on-surface">{selected.vulnerable_template}</pre>
            </div>
            <div>
              <p className="eyebrow mb-2 flex items-center gap-2">
                <CheckCircle size={12} className="text-success" /> Secure · parameterized query / bound values
              </p>
              <pre className="whitespace-pre-wrap break-words rounded border bg-surface-low p-3 font-mono text-xs leading-5 text-on-surface">{selected.secure_template}</pre>
            </div>
          </div>
          <p className="px-5 pb-5 text-xs leading-5 text-on-surface-variant">
            The vulnerable template inserts the payload directly into the SQL string with{' '}
            <code className="font-mono">{'{payload}'}</code>; the parameterized template uses bound placeholders (<code className="font-mono">?</code>).
          </p>
        </Card>
      )}

      {result !== null && (
        <>
          <Card className="mt-5">
            <div className="border-b px-5 py-4">
              <p className="font-display font-semibold flex items-center gap-2">
                <Info size={18} className="text-primary" /> What this run demonstrates
              </p>
            </div>
            <div className="divide-y p-5">
              <ExplanationSection title="What happened?" text={result.explanation.what_happened} />
              <ExplanationSection title="Why the vulnerable query failed" text={result.explanation.why_vulnerable} />
              <ExplanationSection title="Why parameterization works" text={result.explanation.why_safe} />
            </div>
          </Card>

          <Card className="mt-5 border-success/40 bg-success/5 p-5">
            <div className="flex items-start gap-3">
              <ShieldCheck className="mt-0.5 shrink-0 text-success" size={20} />
              <div>
                <p className="font-display font-semibold">How to prevent SQL injection</p>
                <p className="mt-1 text-sm leading-6 text-on-surface-variant">{result.explanation.mitigation}</p>
              </div>
            </div>
          </Card>

          <p className="mt-4 flex items-center gap-2 text-xs text-on-surface-variant">
            <Info size={14} className="shrink-0" />
            <span>
              Execution environment: <code className="font-mono">{result.sandbox}</code>
            </span>
          </p>
        </>
      )}
    </>
  );
}
