import { useState, FormEvent } from 'react';
import { Play, Loader2, AlertCircle, RefreshCw, MailWarning } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import type { EmailAnalysisResult, EmailIndicatorSeverity, EmailRiskLevel } from '../types';

const MAX_CONTENT_LENGTH = 50000;

const severityTone: Record<EmailIndicatorSeverity, 'success' | 'warning' | 'danger' | 'primary'> = {
  High: 'danger',
  Medium: 'warning',
  Low: 'primary',
};

const riskTone: Record<EmailRiskLevel, 'success' | 'warning' | 'danger' | 'primary'> = {
  phishing: 'danger',
  suspicious: 'warning',
  safe: 'success',
};

export function EmailDetectorPage() {
  const [content, setContent] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<EmailAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const trimmed = content.trim();
    if (!trimmed) return;

    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const analysis = await apiClient.post<EmailAnalysisResult>('/email/analyze', { content: trimmed });
      setResult(analysis);
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message || 'Analysis failed. Please try again.');
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Email intelligence"
        title="Phishing Email Detector"
        description="Analyze suspicious message content for phishing language and risky indicators."
        actions={<Button variant="secondary" disabled={isAnalyzing}><RefreshCw size={16} /> History</Button>}
      />
      <div className="grid gap-5 xl:grid-cols-[1fr_0.9fr]">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Run analysis</p>
          <form onSubmit={handleAnalyze} className="mt-6 grid gap-4">
            <label className="grid gap-2 text-sm font-medium">
              <span>Email content</span>
              <textarea
                rows={9}
                value={content}
                onChange={(e) => setContent(e.target.value)}
                disabled={isAnalyzing}
                required
                maxLength={MAX_CONTENT_LENGTH}
                placeholder="Paste a suspicious email message here…"
                className="resize-none rounded border bg-surface-low p-3 font-mono text-sm placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
              />
            </label>
            <Button type="submit" disabled={isAnalyzing || !content.trim()} className="w-full">
              {isAnalyzing ? (
                <>
                  <Loader2 size={16} className="animate-spin mr-2" /> Analyzing…
                </>
              ) : (
                <>
                  <Play size={16} className="mr-2" /> Analyze email
                </>
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
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Risk classification</p>
                  <p className="mt-3 font-display text-4xl font-bold text-on-surface">{result.risk_score} / 100</p>
                  <p className="mt-2 text-sm leading-6 text-on-surface-variant">{result.summary}</p>
                </div>
                <Badge tone={riskTone[result.risk_level]}>
                  {result.risk_level === 'phishing' ? 'Phishing' : result.risk_level === 'suspicious' ? 'Suspicious' : 'Safe'}
                </Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Assessment summary</p>
                <p className="text-sm leading-6 text-on-surface-variant">
                  <code className="font-mono">{result.stats.word_count}</code> words
                  · <code className="font-mono">{result.stats.link_count}</code> link(s)
                  · {Math.round(result.confidence * 100)}% confidence
                  {result.is_phishing && <span> · detected as phishing</span>}
                </p>
                <p className="mt-2 font-mono text-[11px] uppercase tracking-wide text-on-surface-variant/60">{result.analyzer}</p>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Risk classification</p>
                  <p className="mt-3 font-display text-3xl font-bold text-on-surface-variant/40">—</p>
                </div>
                <Badge tone="primary">Ready</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Assessment summary</p>
                <p className="text-sm leading-6 text-on-surface-variant">Paste an email message and start an analysis to see results.</p>
              </div>
            </>
          )}
        </Card>
      </div>

      {result && result.indicators.length > 0 && (
        <Card className="mt-5">
          <div className="border-b px-5 py-4">
            <p className="font-display font-semibold">Detailed findings</p>
          </div>
          <div className="divide-y p-4">
            {result.indicators.map((indicator, index) => (
              <div key={index} className="flex flex-col gap-2 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                  <Badge tone={severityTone[indicator.severity]}>{indicator.severity}</Badge>
                  <div>
                    <p className="font-medium">{indicator.name}</p>
                    <p className="text-sm text-on-surface-variant">{indicator.evidence}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {result && result.indicators.length === 0 && (
        <Card className="mt-5">
          <div className="flex items-center gap-3 px-5 py-4">
            <MailWarning size={18} className="text-on-surface-variant" />
            <p className="text-sm text-on-surface-variant">No phishing indicators detected in this message.</p>
          </div>
        </Card>
      )}
    </>
  );
}