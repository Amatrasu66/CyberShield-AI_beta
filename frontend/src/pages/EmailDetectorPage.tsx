import { useState, FormEvent, ChangeEvent, useRef } from 'react';
import { Play, Loader2, AlertCircle, RefreshCw, MailWarning, ClipboardType, Upload, FileText, X } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import { useSlowRequest } from '../hooks/useSlowRequest';
import { SlowRequestNotice } from '../components/SlowRequestNotice';
import type { EmailAnalysisResult, EmailIndicatorSeverity, EmailRiskLevel } from '../types';

const MAX_CONTENT_LENGTH = 50000;

// Mirrors the backend's PDF upload ceiling: EMAIL_PDF_MAX_SIZE and the global
// MAX_CONTENT_LENGTH both default to 1 MB, so the effective limit is 1 MB.
const MAX_PDF_SIZE_BYTES = 1_000_000;

type InputMode = 'text' | 'pdf';

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
  const [mode, setMode] = useState<InputMode>('text');
  const [content, setContent] = useState('');
  const [pdfFile, setPdfFile] = useState<File | null>(null);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<EmailAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { run, isSlow, elapsedSeconds } = useSlowRequest();

  const switchMode = (next: InputMode) => {
    if (next === mode) return;
    setMode(next);
    setError(null);
    setPdfError(null);
    if (next === 'text') {
      setPdfFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
    } else {
      setContent('');
    }
  };

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0] ?? null;
    event.target.value = '';
    setPdfError(null);

    if (!file) {
      setPdfFile(null);
      return;
    }

    const looksLikePdf =
      file.type === 'application/pdf' ||
      file.type === 'application/x-pdf' ||
      file.name.toLowerCase().endsWith('.pdf');
    if (!looksLikePdf) {
      setPdfFile(null);
      setPdfError('Please choose a PDF file.');
      return;
    }
    if (file.size > MAX_PDF_SIZE_BYTES) {
      setPdfFile(null);
      setPdfError('The PDF exceeds the 1 MB size limit.');
      return;
    }
    if (file.size === 0) {
      setPdfFile(null);
      setPdfError('The selected file is empty.');
      return;
    }
    setPdfFile(file);
  };

  const removePdf = () => {
    setPdfFile(null);
    setPdfError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleAnalyze = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isAnalyzing) return;
    if (mode === 'text' && !content.trim()) return;
    if (mode === 'pdf' && (!pdfFile || pdfError)) return;

    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      if (mode === 'text') {
        const analysis = await run(() => apiClient.post<EmailAnalysisResult>('/email/analyze', { content: content.trim() }));
        setResult(analysis);
      } else {
        const formData = new FormData();
        formData.append('file', pdfFile as File);
        const analysis = await run(() => apiClient.postForm<EmailAnalysisResult>('/email/analyze', formData));
        setResult(analysis);
      }
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

  const canSubmit =
    mode === 'text' ? Boolean(content.trim()) : Boolean(pdfFile && !pdfError);

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
            <div className="grid gap-2 text-sm font-medium">
              <span>Input method</span>
              <div className="grid grid-cols-2 gap-2" role="tablist" aria-label="Email input method">
                <button
                  type="button"
                  role="tab"
                  aria-selected={mode === 'text'}
                  onClick={() => switchMode('text')}
                  className={
                    'inline-flex h-10 items-center justify-center gap-2 rounded border px-3 text-sm font-semibold transition ' +
                    (mode === 'text'
                      ? 'border-primary bg-primary/10 text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60'
                      : 'bg-surface-low text-on-surface-variant hover:bg-surface-high focus:outline-none focus:ring-2 focus:ring-primary/60')
                  }
                >
                  <ClipboardType size={16} /> Paste email text
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={mode === 'pdf'}
                  onClick={() => switchMode('pdf')}
                  className={
                    'inline-flex h-10 items-center justify-center gap-2 rounded border px-3 text-sm font-semibold transition ' +
                    (mode === 'pdf'
                      ? 'border-primary bg-primary/10 text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60'
                      : 'bg-surface-low text-on-surface-variant hover:bg-surface-high focus:outline-none focus:ring-2 focus:ring-primary/60')
                  }
                >
                  <Upload size={16} /> Upload PDF
                </button>
              </div>
              <p className="text-xs leading-5 text-on-surface-variant">
                Choose one: paste the email text, or upload a text-based email PDF. PDFs are
                extracted server-side and analyzed with the same engine.
              </p>
            </div>

            {mode === 'text' ? (
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
            ) : (
              <div className="grid gap-2">
                <span className="text-sm font-medium">Email PDF</span>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="application/pdf,.pdf"
                  onChange={handleFileChange}
                  disabled={isAnalyzing}
                  className="sr-only"
                  data-testid="pdf-upload-input"
                />
                {pdfFile ? (
                  <div className="flex items-center justify-between gap-3 rounded border bg-surface-low p-3">
                    <div className="flex min-w-0 items-center gap-3">
                      <span className="grid h-10 w-10 shrink-0 place-items-center rounded bg-primary/10 text-primary">
                        <FileText size={18} />
                      </span>
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">{pdfFile.name}</span>
                        <span className="block text-xs text-on-surface-variant">
                          {(pdfFile.size / 1024).toFixed(1)} KB · ready to analyze
                        </span>
                      </span>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <Button
                        type="button"
                        variant="ghost"
                        className="h-9 px-2 text-xs"
                        disabled={isAnalyzing}
                        onClick={() => fileInputRef.current?.click()}
                      >
                        Change
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        className="h-9 px-2 text-xs"
                        disabled={isAnalyzing}
                        aria-label="Remove PDF"
                        title="Remove PDF"
                        onClick={removePdf}
                      >
                        <X size={16} />
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div>
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={isAnalyzing}
                      className="w-full rounded border border-dashed bg-surface-low p-6 text-center transition hover:border-primary hover:bg-primary/5 focus:outline-none focus:ring-2 focus:ring-primary/60 disabled:opacity-60"
                    >
                      <Upload size={20} className="mx-auto text-on-surface-variant" />
                      <span className="mt-2 block text-sm font-semibold">Click to select a PDF</span>
                      <span className="mt-1 block text-xs text-on-surface-variant">
                        Text-based email PDFs only · up to 1 MB
                      </span>
                    </button>
                    {pdfError && (
                      <p className="mt-2 flex items-center gap-2 text-xs text-destructive">
                        <AlertCircle size={14} /> {pdfError}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}

            <Button type="submit" disabled={isAnalyzing || !canSubmit} className="w-full">
              {isAnalyzing ? (
                <>
                  <Loader2 size={16} className="animate-spin mr-2" /> Analyzing…
                </>
              ) : mode === 'pdf' ? (
                <>
                  <Upload size={16} className="mr-2" /> Analyze PDF
                </>
              ) : (
                <>
                  <Play size={16} className="mr-2" /> Analyze email
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
                <p className="text-sm leading-6 text-on-surface-variant">Paste an email message or upload an email PDF and start an analysis to see results.</p>
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