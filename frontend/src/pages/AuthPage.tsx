import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { authContent } from '../data/mockData';
import { Button, TextInput } from '../components/ui';
import { BrandLogo } from '../components/BrandLogo';
import { PasswordInput } from '../components/PasswordInput';
import { useAuth } from '../context/AuthContext';

export interface AuthPageProps { readonly mode: keyof typeof authContent; }
export function AuthPage({ mode }: AuthPageProps) {
  const content = authContent[mode];
  const reset = mode === 'forgot';
  const { signIn, signUp, sendPasswordReset } = useAuth();
  const navigate = useNavigate();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setMessage(null);

    if (reset) {
      if (!email.trim()) {
        setError('Please enter your email address.');
        return;
      }
      setSubmitting(true);
      try {
        await sendPasswordReset(email.trim());
        setMessage('If an account exists for that email, you will receive a password reset link shortly.');
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to send reset link. Please try again.');
      } finally {
        setSubmitting(false);
      }
      return;
    }

    if (mode === 'register') {
      if (password !== confirmPassword) {
        setError('Passwords do not match.');
        return;
      }
      if (password.length < 8) {
        setError('Password must be at least 8 characters.');
        return;
      }
    }

    setSubmitting(true);
    try {
      if (mode === 'register') {
        const signedIn = await signUp(email, password, fullName.trim() || undefined);
        if (!signedIn) {
          setMessage('Account created. Check your email to confirm your address, then sign in.');
          return;
        }
      } else {
        await signIn(email, password);
      }
      navigate('/dashboard', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="grid min-h-screen bg-background lg:grid-cols-2">
      <section className="relative hidden overflow-hidden border-r bg-surface-lowest p-12 lg:block">
        <div className="grid-glow absolute inset-0" />
        <div className="relative flex h-full flex-col justify-between">
          <BrandLogo className="h-8 w-auto max-w-[190px]" />
          <div className="max-w-md">
            <p className="eyebrow mb-4">Security intelligence</p>
            <h1 className="font-display text-5xl font-bold leading-tight tracking-tight">
              Know your exposure. <span className="text-primary">Act with confidence.</span>
            </h1>
            <p className="mt-5 leading-7 text-on-surface-variant">A focused workspace for security checks, incident insights, and practical remediation.</p>
          </div>
          <p className="font-mono text-xs text-on-surface-variant">CYBERSHIELD AI · STATIC PRODUCT DEMO</p>
        </div>
      </section>

      <section className="flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          <Link to="/dashboard" className="mb-10 inline-flex lg:hidden" aria-label="CyberShield — Go to dashboard">
            <BrandLogo className="h-8 w-auto max-w-[180px]" />
          </Link>
          <p className="eyebrow mb-3">Secure access</p>
          <h2 className="font-display text-3xl font-bold">{content.title}</h2>
          <p className="mt-3 text-sm leading-6 text-on-surface-variant">{content.description}</p>

          {error !== null && <p className="mt-4 rounded border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">{error}</p>}
          {message !== null && <p className="mt-4 rounded border border-success/30 bg-success/10 px-4 py-3 text-sm text-success">{message}</p>}

          <form className="mt-8 grid gap-5" onSubmit={handleSubmit} noValidate>
            {!reset && mode === 'register' && (
              <TextInput
                label="Full name"
                placeholder="Avery Sharma"
                value={fullName}
                onChange={(event) => setFullName(event.target.value)}
                autoComplete="name"
              />
            )}

            <TextInput
              label="Email address"
              type="email"
              autoComplete="email"
              required
              placeholder="you@company.com"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />

            {!reset && (
              <>
                <PasswordInput
                  label="Password"
                  autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  maxLength={4096}
                />
                {mode === 'register' && (
                  <PasswordInput
                    label="Confirm password"
                    autoComplete="new-password"
                    required
                    placeholder="••••••••••••"
                    value={confirmPassword}
                    onChange={(event) => setConfirmPassword(event.target.value)}
                    maxLength={4096}
                  />
                )}
              </>
            )}

            {mode === 'login' && (
              <div className="text-right">
                <Link to="/forgot-password" className="text-sm font-medium text-primary hover:underline">
                  Forgot password?
                </Link>
              </div>
            )}

            <Button type="submit" className="mt-2 w-full" disabled={submitting}>
              {content.action}
            </Button>
          </form>

          <p className="mt-6 text-center text-sm text-on-surface-variant">
            {content.prompt} <Link className="font-semibold text-primary hover:underline" to={content.to}>{content.link}</Link>
          </p>
        </div>
      </section>
    </main>
  );
}
