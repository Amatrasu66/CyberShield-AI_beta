import { useState, FormEvent, useRef, useEffect, useCallback } from 'react';
import {
  Play,
  Loader2,
  AlertCircle,
  RefreshCw,
  Eye,
  EyeOff,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Shield,
  AlertOctagon,
  ListChecks,
  BarChart2,
  Copy,
  Check,
  Sparkles,
  Zap,
  ArrowRight,
  Lock,
  Unlock,
  Info,
  HelpCircle,
} from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card } from '../components/ui';
import { apiClient, ApiClientError } from '../services/apiClient';
import { useSlowRequest } from '../hooks/useSlowRequest';
import { SlowRequestNotice } from '../components/SlowRequestNotice';
import type { PasswordAnalysisResult, PasswordStrengthLabel, PasswordWeakness, PasswordScoreBreakdown, PasswordChecklistItem, PasswordGenerateResult } from '../types';
import type { LucideIcon } from 'lucide-react';

interface ComparisonState {
  current: PasswordAnalysisResult | null;
  generated: PasswordAnalysisResult | null;
  showComparison: boolean;
}

const strengthTone: Record<PasswordStrengthLabel, 'success' | 'warning' | 'danger' | 'primary'> = {
  Strong: 'success',
  Good: 'primary',
  Fair: 'warning',
  Weak: 'danger',
};

const strengthIcon: Record<PasswordStrengthLabel, LucideIcon> = {
  Strong: CheckCircle,
  Good: CheckCircle,
  Fair: AlertTriangle,
  Weak: XCircle,
};

const severityTone = (severity: string): 'success' | 'warning' | 'danger' | 'primary' => {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'danger';
    case 'medium':
      return 'warning';
    case 'low':
      return 'primary';
    default:
      return 'primary';
  }
};

const severityIcon = (severity: string): LucideIcon => {
  switch (severity) {
    case 'critical':
    case 'high':
      return AlertOctagon;
    case 'medium':
      return AlertTriangle;
    case 'low':
      return AlertCircle;
    default:
      return AlertCircle;
  }
};

const classTone = (met: boolean) => (met ? 'success' : 'danger');

const statusTone = (status: string): 'success' | 'warning' | 'danger' | 'primary' => {
  switch (status) {
    case 'good':
      return 'success';
    case 'warning':
      return 'warning';
    case 'danger':
      return 'danger';
    default:
      return 'primary';
  }
};

const statusIcon = (status: string): LucideIcon => {
  switch (status) {
    case 'good':
      return CheckCircle;
    case 'warning':
      return AlertTriangle;
    case 'danger':
      return XCircle;
    default:
      return AlertCircle;
  }
};

const checklistStatus = (item: PasswordChecklistItem): 'passed' | 'failed' | 'advisory' =>
  item.status ?? (item.passed === null || item.passed === undefined ? 'advisory' : item.passed ? 'passed' : 'failed');

const checklistIcon = (status: string): LucideIcon => {
  switch (status) {
    case 'passed': return CheckCircle;
    case 'failed': return XCircle;
    case 'advisory': return Info;
    default: return AlertCircle;
  }
};

const checklistTone = (status: string): 'success' | 'warning' | 'danger' | 'primary' => {
  switch (status) {
    case 'passed': return 'success';
    case 'failed': return 'danger';
    case 'advisory': return 'primary';
    default: return 'primary';
  }
};

const checklistIconTone = (status: string): string => {
  switch (status) {
    case 'passed': return 'text-success mr-1';
    case 'failed': return 'text-danger mr-1';
    case 'advisory': return 'text-primary mr-1';
    default: return 'mr-1';
  }
};

const checklistLabel = (status: string): string => {
  switch (status) {
    case 'passed': return 'Passed';
    case 'failed': return 'Failed';
    case 'advisory': return 'Advisory';
    default: return status;
  }
};

const IconWrapper = ({ icon: Icon, size = 12, className = '' }: { icon: LucideIcon; size?: number; className?: string }) => (
  <Icon size={size} className={className} />
);

export function PasswordAnalyzerPage() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [comparison, setComparison] = useState<ComparisonState>({
    current: null,
    generated: null,
    showComparison: false,
  });
  const [error, setError] = useState<string | null>(null);
  const [generatedPassword, setGeneratedPassword] = useState<PasswordGenerateResult | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);
  const passwordInputRef = useRef<HTMLInputElement>(null);
  const { run, isSlow, elapsedSeconds } = useSlowRequest();

  useEffect(() => {
    return () => {
      setPassword('');
      setGeneratedPassword(null);
    };
  }, []);

  const handleAnalyze = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isAnalyzing) return;
    if (!password.trim()) return;

    setIsAnalyzing(true);
    setError(null);

    try {
      const analysis = await run(() => apiClient.post<PasswordAnalysisResult>('/password/analyze', { password: password.trim() }));
      setComparison(prev => ({
        ...prev,
        current: analysis,
        showComparison: prev.generated !== null,
      }));
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message || 'Analysis failed. Please try again.');
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsAnalyzing(false);
      setPassword('');
      passwordInputRef.current?.blur();
    }
  };

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    setError(null);
  };

  const handleGenerate = useCallback(async (type: 'passphrase' | 'random', options?: { words?: number; length?: number }) => {
    setIsGenerating(true);
    setError(null);

    try {
      const response = await run(() => apiClient.post<PasswordGenerateResult>('/password/generate', {
        type,
        ...options,
      }));
      setGeneratedPassword(response);
      setCopySuccess(false);
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message || 'Generation failed. Please try again.');
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsGenerating(false);
    }
  }, []);

  const handleAnalyzeGenerated = useCallback(async () => {
    if (!generatedPassword) return;
    setIsAnalyzing(true);
    setError(null);

    try {
      const analysis = await run(() => apiClient.post<PasswordAnalysisResult>('/password/analyze', { password: generatedPassword.password }));
      setComparison(prev => ({
        ...prev,
        generated: analysis,
        showComparison: prev.current !== null,
      }));
      setGeneratedPassword(null);
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message || 'Analysis failed. Please try again.');
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsAnalyzing(false);
    }
  }, [generatedPassword]);

  const handleAnalyzeAnother = useCallback(() => {
    setComparison({
      current: null,
      generated: null,
      showComparison: false,
    });
    setError(null);
  }, []);

  const handleCopy = async () => {
    if (!generatedPassword) return;
    try {
      await navigator.clipboard.writeText(generatedPassword.password);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch {
      // Clipboard API failed, silently ignore
    }
  };

  const canSubmit = Boolean(password.trim());

  const result = comparison.current;
  const generatedResult = comparison.generated;
  const showComparison = comparison.showComparison;

  return (
    <>
      <PageHeader
        eyebrow="Credential hygiene"
        title="Password Security Advisor"
        description="Analyze password strength with detailed weakness explanations, score breakdown, and security checklist."
        actions={<Button variant="secondary" disabled={isAnalyzing}><RefreshCw size={16} /> History</Button>}
      />
      <div className="grid gap-5 xl:grid-cols-[1fr_0.9fr]">
        <Card className="p-5">
          <p className="font-display text-lg font-semibold">Run analysis</p>
          <form onSubmit={handleAnalyze} className="mt-6 grid gap-4">
            <label className="grid gap-2 text-sm font-medium">
              <span>Password to assess</span>
              <div className="relative">
                <input
                  ref={passwordInputRef}
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={handlePasswordChange}
                  disabled={isAnalyzing}
                  required
                  maxLength={4096}
                  placeholder="Enter a password to analyze"
                  className="h-11 rounded border bg-surface-low px-3 pr-12 placeholder:text-on-surface-variant/60 focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
                  autoComplete="new-password"
                  aria-label="Password to analyze"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={isAnalyzing}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface focus:outline-none focus:ring-2 focus:ring-primary/60 rounded"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </label>

            <Button type="submit" disabled={isAnalyzing || !canSubmit} className="w-full">
              {isAnalyzing ? (
                <>
                  <Loader2 size={16} className="animate-spin mr-2" /> Analyzing…
                </>
              ) : (
                <>
                  <Play size={16} className="mr-2" /> Analyze password
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
              The password is sent only to the analysis endpoint and is never stored or logged. It is cleared from this page after analysis.
            </p>
          </form>
        </Card>

        <Card className="p-5">
          {result ? (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Strength rating</p>
                  <div className="mt-2 flex items-center gap-3">
                    <p className="font-display text-4xl font-bold text-on-surface">{result.strength_score} / 100</p>
                    <Badge tone={strengthTone[result.strength]}>
                      <IconWrapper icon={strengthIcon[result.strength]} size={12} className="mr-1" />
                      {result.strength}
                    </Badge>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-on-surface-variant">
                    Entropy: <code className="font-mono">{result.entropy_bits.toFixed(2)}</code> bits
                    · Crack time estimate: <code className="font-mono">{result.crack_time_estimate}</code>
                    {result.in_common_list && (
                      <> · <span className="text-destructive">Found in common password lists</span></>
                    )}
                  </p>
                </div>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Character composition</p>
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                  <Badge tone={classTone(result.uppercase)}>
                    <IconWrapper icon={result.uppercase ? CheckCircle : XCircle} size={12} className={result.uppercase ? 'text-success mr-1' : 'text-danger mr-1'} />
                    Uppercase
                  </Badge>
                  <Badge tone={classTone(result.lowercase)}>
                    <IconWrapper icon={result.lowercase ? CheckCircle : XCircle} size={12} className={result.lowercase ? 'text-success mr-1' : 'text-danger mr-1'} />
                    Lowercase
                  </Badge>
                  <Badge tone={classTone(result.digits)}>
                    <IconWrapper icon={result.digits ? CheckCircle : XCircle} size={12} className={result.digits ? 'text-success mr-1' : 'text-danger mr-1'} />
                    Digits
                  </Badge>
                  <Badge tone={classTone(result.special)}>
                    <IconWrapper icon={result.special ? CheckCircle : XCircle} size={12} className={result.special ? 'text-success mr-1' : 'text-danger mr-1'} />
                    Special
                  </Badge>
                </div>
                <div className="mt-4 grid gap-2 sm:grid-cols-3">
                  <div className="text-sm text-on-surface-variant">
                    Length: <code className="font-mono text-on-surface">{result.length}</code> characters
                  </div>
                  <div className="text-sm text-on-surface-variant">
                    Classes used: <code className="font-mono text-on-surface">{result.classes_used}</code> / 4
                  </div>
                  <div className="text-sm text-on-surface-variant">
                    In common list: <code className="font-mono text-on-surface">{result.in_common_list ? 'Yes' : 'No'}</code>
                  </div>
                </div>
              </div>

              {/* Weaknesses Section */}
              {result.weaknesses.length > 0 && (
                <Card className="mt-5">
                  <div className="border-b px-5 py-4">
                    <p className="font-display font-semibold flex items-center gap-2">
                      <Shield size={18} className="text-warning" />
                      Why this password received this score
                    </p>
                  </div>
                  <div className="divide-y p-4">
{result.weaknesses.map((weakness: PasswordWeakness, index: number) => {
                      const Icon = severityIcon(weakness.severity);
                      const tone = severityTone(weakness.severity);
                      return (
                        <div key={index} className="py-3">
                          <div className="flex items-start gap-3">
                            <Badge tone={tone}>
                              <IconWrapper icon={Icon} size={12} className="mr-1" />
                              {weakness.severity.toUpperCase()}
                            </Badge>
                            <div className="flex-1">
                              <p className="font-medium text-on-surface">{weakness.title}</p>
                              <p className="text-sm text-on-surface-variant mt-1">{weakness.message}</p>
                              <p className="text-sm text-primary mt-2 font-medium">{weakness.recommendation}</p>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Card>
              )}

              {/* Score Breakdown Section */}
              {result.score_breakdown.length > 0 && (
                <Card className="mt-5">
                  <div className="border-b px-5 py-4">
                    <p className="font-display font-semibold flex items-center gap-2">
                      <BarChart2 size={18} className="text-primary" />
                      Score Breakdown
                    </p>
                  </div>
                  <div className="divide-y p-4">
                    {result.score_breakdown.map((factor: PasswordScoreBreakdown, index: number) => {
                      const Icon = statusIcon(factor.status);
                      const tone = statusTone(factor.status);
                      return (
                        <div key={index} className="py-3 flex items-center justify-between gap-4">
                          <div className="flex items-center gap-3 flex-1">
                            <Badge tone={tone}>
                              <IconWrapper icon={Icon} size={12} className="mr-1" />
                              {factor.status.toUpperCase()}
                            </Badge>
                            <div>
                              <p className="font-medium text-on-surface">{factor.factor}</p>
                              <p className="text-sm text-on-surface-variant">{factor.details}</p>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="font-display text-xl font-bold text-on-surface">{factor.score}%</p>
                            <p className="text-xs text-on-surface-variant">of 100</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Card>
              )}

              {/* Security Checklist Section */}
              {result.security_checklist.length > 0 && (
                <Card className="mt-5">
                  <div className="border-b px-5 py-4">
                    <p className="font-display font-semibold flex items-center gap-2">
                      <ListChecks size={18} className="text-primary" />
                      Security Checklist
                    </p>
                    <p className="mt-1 text-xs leading-5 text-on-surface-variant">
                      Passed/Failed items are verified against the submitted password. Advisory items are recommendations that this tool cannot verify.
                    </p>
                  </div>
                  <div className="divide-y p-4">
                    {result.security_checklist.map((item: PasswordChecklistItem, index: number) => {
                      const status = checklistStatus(item);
                      const Icon = checklistIcon(status);
                      const tone = checklistTone(status);
                      return (
                        <div key={index} className="py-3 flex items-start gap-3">
                          <Badge tone={tone}>
                            <IconWrapper icon={Icon} size={12} className={checklistIconTone(status)} />
                            {checklistLabel(status)}
                          </Badge>
                          <div className="flex-1">
                            <p className="font-medium text-on-surface">{item.item}</p>
                            <p className="text-sm text-on-surface-variant mt-1">{item.details}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </Card>
              )}

            </>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-on-surface-variant">Strength rating</p>
                  <p className="mt-3 font-display text-3xl font-bold text-on-surface-variant/40">—</p>
                </div>
                <Badge tone="primary">Ready</Badge>
              </div>
              <div className="mt-6 rounded border bg-surface-low p-4">
                <p className="eyebrow mb-2">Assessment summary</p>
                <p className="text-sm leading-6 text-on-surface-variant">Enter a password and start the analysis to see detailed strength metrics and recommendations.</p>
              </div>
            </>
          )}
        </Card>
      </div>

      {/* Generate Stronger Password Section */}
      <Card className="mt-5">
        <div className="border-b px-5 py-4">
          <p className="font-display font-semibold flex items-center gap-2">
            <Sparkles size={18} className="text-primary" />
            Generate a stronger password
          </p>
        </div>
        <div className="p-5 grid gap-4 sm:grid-cols-2">
          {/* Passphrase Generator */}
          <div className="space-y-3 p-4 rounded border bg-surface-low">
            <div className="flex items-center gap-2">
              <Zap size={16} className="text-primary" />
              <p className="font-medium text-on-surface">Passphrase</p>
            </div>
            <p className="text-sm text-on-surface-variant">
              Random words combined with a delimiter. Easier to remember and type.
            </p>
            <div className="grid gap-2 sm:grid-cols-3">
              <label className="text-sm text-on-surface-variant">
                Words
                <select
                  value={5}
                  onChange={(e) => handleGenerate('passphrase', { words: parseInt(e.target.value) })}
                  disabled={isGenerating}
                  className="mt-1 block w-full h-10 rounded border bg-surface px-3 text-on-surface focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
                >
                  <option value={4}>4</option>
                  <option value={5} selected>5 (default)</option>
                  <option value={6}>6</option>
                </select>
              </label>
            </div>
            <Button
              onClick={() => handleGenerate('passphrase', { words: 5 })}
              disabled={isGenerating}
              variant="primary"
              className="w-full"
            >
              {isGenerating ? (
                <>
                  <Loader2 size={16} className="animate-spin mr-2" /> Generating…
                </>
              ) : (
                <>
                  <Sparkles size={16} className="mr-2" /> Generate Passphrase
                </>
              )}
            </Button>
          </div>

          {/* Random Password Generator */}
          <div className="space-y-3 p-4 rounded border bg-surface-low">
            <div className="flex items-center gap-2">
              <Zap size={16} className="text-warning" />
              <p className="font-medium text-on-surface">Random Password</p>
            </div>
            <p className="text-sm text-on-surface-variant">
              Cryptographically secure random characters. Maximum entropy.
            </p>
            <div className="grid gap-2 sm:grid-cols-3">
              <label className="text-sm text-on-surface-variant">
                Length
                <select
                  value={20}
                  onChange={(e) => handleGenerate('random', { length: parseInt(e.target.value) })}
                  disabled={isGenerating}
                  className="mt-1 block w-full h-10 rounded border bg-surface px-3 text-on-surface focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/20"
                >
                  <option value={16}>16</option>
                  <option value={20} selected>20 (default)</option>
                  <option value={24}>24</option>
                  <option value={32}>32</option>
                </select>
              </label>
            </div>
            <Button
              onClick={() => handleGenerate('random', { length: 20 })}
              disabled={isGenerating}
              variant="primary"
              className="w-full"
            >
              {isGenerating ? (
                <>
                  <Loader2 size={16} className="animate-spin mr-2" /> Generating…
                </>
              ) : (
                <>
                  <Zap size={16} className="mr-2" /> Generate Random Password
                </>
              )}
            </Button>
          </div>
        </div>

        {isGenerating && isSlow && (
          <div className="border-t p-5">
            <SlowRequestNotice elapsedSeconds={elapsedSeconds} />
          </div>
        )}

        {/* Generated Password Display */}
        {generatedPassword && (
          <div className="border-t p-5 space-y-4">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-2">
                  <Badge tone={generatedPassword.type === 'passphrase' ? 'primary' : 'warning'}>
                    {generatedPassword.type === 'passphrase' ? (
                      <>
                        <Sparkles size={12} className="mr-1" /> Passphrase
                      </>
                    ) : (
                      <>
                        <Zap size={12} className="mr-1" /> Random
                      </>
                    )}
                  </Badge>
                  <span className="text-sm text-on-surface-variant">
                    {generatedPassword.type === 'passphrase'
                      ? `${generatedPassword.words} words · ${generatedPassword.length} chars`
                      : `${generatedPassword.length} chars · ${generatedPassword.charset_size} charset`}
                  </span>
                </div>
                <div className="relative">
                  <code className="font-mono text-base text-on-surface break-all block bg-surface-low px-4 py-3 rounded border">
                    {generatedPassword.password}
                  </code>
                  <Button
                    onClick={handleCopy}
                    variant="ghost"
                    className="absolute right-2 top-2 h-8 px-3"
                    aria-label={copySuccess ? 'Copied!' : 'Copy to clipboard'}
                  >
                    {copySuccess ? (
                      <Check size={16} className="text-success" />
                    ) : (
                      <Copy size={16} />
                    )}
                  </Button>
                </div>
              </div>
            </div>
            <Button
              onClick={handleAnalyzeGenerated}
              disabled={isAnalyzing}
              variant="secondary"
              className="w-full sm:w-auto"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 size={16} className="animate-spin mr-2" /> Analyzing…
                </>
              ) : (
                <>
                  <Play size={16} className="mr-2" /> Analyze this password
                </>
              )}
            </Button>
            <p className="text-xs text-on-surface-variant">
              Generated passwords are never stored or logged. They exist only in this browser session.
            </p>
          </div>
        )}
      </Card>

      {result && result.recommendations.length > 0 && (
        <Card className="mt-5">
          <div className="border-b px-5 py-4">
            <p className="font-display font-semibold">Recommendations</p>
          </div>
          <div className="divide-y p-4">
            {result.recommendations.map((rec, index) => (
              <div key={index} className="flex items-start gap-3 py-3">
                <Badge tone={rec.priority <= 2 ? 'danger' : rec.priority <= 4 ? 'warning' : 'primary'}>
                  P{rec.priority}
                </Badge>
                <p className="text-sm text-on-surface">{rec.text}</p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {result && result.recommendations.length === 0 && (
        <Card className="mt-5">
          <div className="flex items-center gap-3 px-5 py-4">
            <CheckCircle size={18} className="text-success" />
            <p className="text-sm text-on-surface-variant">No specific recommendations — this password meets strong security criteria.</p>
          </div>
        </Card>
      )}

      {/* Comparison Section */}
      {showComparison && result && generatedResult && (
        <Card className="mt-5">
          <div className="border-b px-5 py-4">
            <p className="font-display font-semibold flex items-center gap-2">
              <ArrowRight size={18} className="text-primary" />
              Comparison: Current vs Generated
            </p>
          </div>
          <div className="p-5">
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Current Password Column */}
              <div className="space-y-4 p-4 rounded border bg-surface-low">
                <div className="flex items-center gap-2">
                  <Lock size={16} className="text-warning" />
                  <p className="font-medium text-on-surface">Current Password</p>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Score</span>
                    <span className="font-display text-xl font-bold text-on-surface">{result.strength_score} / 100</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Strength</span>
                    <Badge tone={strengthTone[result.strength]}>
                      <IconWrapper icon={strengthIcon[result.strength]} size={12} className="mr-1" />
                      {result.strength}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Length</span>
                    <span className="font-mono text-on-surface">{result.length} chars</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Crack time</span>
                    <span className="font-mono text-on-surface">{result.crack_time_estimate}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">In common list</span>
                    <span className={`font-mono text-on-surface ${result.in_common_list ? 'text-destructive' : 'text-success'}`}>
                      {result.in_common_list ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Weaknesses</span>
                    <span className="font-mono text-on-surface">{result.weaknesses.length}</span>
                  </div>
                </div>
              </div>

              {/* Generated Password Column */}
              <div className="space-y-4 p-4 rounded border bg-surface-low">
                <div className="flex items-center gap-2">
                  <Unlock size={16} className="text-success" />
                  <p className="font-medium text-on-surface">Generated Alternative</p>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Score</span>
                    <span className="font-display text-xl font-bold text-on-surface">{generatedResult.strength_score} / 100</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Strength</span>
                    <Badge tone={strengthTone[generatedResult.strength]}>
                      <IconWrapper icon={strengthIcon[generatedResult.strength]} size={12} className="mr-1" />
                      {generatedResult.strength}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Length</span>
                    <span className="font-mono text-on-surface">{generatedResult.length} chars</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Crack time</span>
                    <span className="font-mono text-on-surface">{generatedResult.crack_time_estimate}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">In common list</span>
                    <span className={`font-mono text-on-surface ${generatedResult.in_common_list ? 'text-destructive' : 'text-success'}`}>
                      {generatedResult.in_common_list ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-on-surface-variant">Weaknesses</span>
                    <span className="font-mono text-on-surface">{generatedResult.weaknesses.length}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Improvement Summary */}
            <div className="mt-6 p-4 rounded bg-primary/10 border border-primary/20">
              <div className="flex items-center gap-2 mb-2">
                <ArrowRight size={16} className="text-primary" />
                <p className="font-medium text-on-surface">Improvement</p>
              </div>
              <div className="grid gap-2 sm:grid-cols-3 text-sm">
                <div>
                  <span className="text-on-surface-variant">Score change: </span>
                  <span className={`font-mono ${generatedResult.strength_score >= result.strength_score ? 'text-success' : 'text-destructive'}`}>
                    {generatedResult.strength_score - result.strength_score >= 0 ? '+' : ''}{generatedResult.strength_score - result.strength_score}
                  </span>
                </div>
                <div>
                  <span className="text-on-surface-variant">Length change: </span>
                  <span className={`font-mono ${generatedResult.length >= result.length ? 'text-success' : 'text-destructive'}`}>
                    {generatedResult.length - result.length >= 0 ? '+' : ''}{generatedResult.length - result.length} chars
                  </span>
                </div>
                <div>
                  <span className="text-on-surface-variant">Weaknesses resolved: </span>
                  <span className={`font-mono ${generatedResult.weaknesses.length <= result.weaknesses.length ? 'text-success' : 'text-destructive'}`}>
                    {result.weaknesses.length - generatedResult.weaknesses.length >= 0 ? '+' : ''}{result.weaknesses.length - generatedResult.weaknesses.length}
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-4 flex gap-3">
              <Button onClick={handleAnalyzeAnother} variant="secondary" className="w-full sm:w-auto">
                <RefreshCw size={16} className="mr-2" /> Analyze another password
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Privacy Panel */}
      <Card className="mt-5">
        <div className="border-b px-5 py-4">
          <p className="font-display font-semibold flex items-center gap-2">
            <Info size={18} className="text-primary" />
            Privacy & Security
          </p>
        </div>
        <div className="p-5 space-y-3 text-sm text-on-surface-variant">
          <div className="flex items-start gap-3">
            <Lock size={18} className="text-primary shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-on-surface">Your password is analyzed in memory and is not stored as plaintext.</p>
              <p className="mt-1">Only derived metrics (length, entropy, strength score, character classes, breach status) are persisted to your account. The plaintext password is never written to logs, databases, or analytics.</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <HelpCircle size={18} className="text-primary shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-on-surface">Generated passwords are never stored.</p>
              <p className="mt-1">Generated passphrases and random passwords exist only in your browser session. They are not logged, persisted, or sent to any external service.</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Shield size={18} className="text-primary shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-on-surface">MFA was not evaluated because this tool cannot inspect your account configuration.</p>
              <p className="mt-1">We strongly recommend enabling multi-factor authentication (MFA) wherever available. MFA adds a critical second layer of security beyond the password.</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <Sparkles size={18} className="text-primary shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-on-surface">Security recommendations are contextual, not absolute.</p>
              <p className="mt-1">This tool cannot determine whether you reuse passwords across other services. Always use a unique password for each account. Consider using a password manager to generate and store unique credentials.</p>
            </div>
          </div>
        </div>
      </Card>
    </>
  );
}