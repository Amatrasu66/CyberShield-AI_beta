import { useState, type FormEvent, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertCircle, CheckCircle, Loader2 } from 'lucide-react';
import { BrandLogo, BrandMark } from '../components/BrandLogo';
import { PasswordInput } from '../components/PasswordInput';
import { Button } from '../components/ui';
import { useAuth } from '../context/AuthContext';
import { supabase } from '../services/supabaseClient';

export function ResetPasswordPage() {
  const { updatePassword } = useAuth();
  const navigate = useNavigate();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [checkingSession, setCheckingSession] = useState(true);
  const [hasSession, setHasSession] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function check() {
      // Detect recovery session; also handle code exchange if needed
      const url = new URL(window.location.href);
      const code = url.searchParams.get('code');
      if (code) {
        const { error: exErr } = await supabase.auth.exchangeCodeForSession(window.location.href);
        if (exErr && !cancelled) {
          setError('Recovery link is invalid or has expired. Please request a new reset link.');
          setCheckingSession(false);
          return;
        }
      }
      const { data } = await supabase.auth.getSession();
      if (!cancelled) {
        setHasSession(data.session !== null);
        setCheckingSession(false);
      }
    }
    void check();
    return () => {
      cancelled = true;
    };
  }, []);

  function validate(): string | null {
    if (newPassword.length < 8) return 'Password must be at least 8 characters.';
    if (newPassword.length > 4096) return 'Password is too long.';
    if (newPassword !== confirmPassword) return 'Passwords do not match.';
    return null;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const validation = validate();
    if (validation) {
      setError(validation);
      return;
    }
    setSubmitting(true);
    try {
      await updatePassword(newPassword);
      setSuccess(true);
      // Clear sensitive state
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => navigate('/dashboard', { replace: true }), 1500);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Password update failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  if (checkingSession) {
    return (
      <main className="grid min-h-screen place-items-center bg-background p-6">
        <div className="flex flex-col items-center gap-3">
          <BrandMark className="h-12 w-12 animate-pulse" decorative={false} />
          <p className="flex items-center gap-2 text-sm text-on-surface-variant">
            <Loader2 size={16} className="animate-spin" /> Verifying recovery link…
          </p>
        </div>
      </main>
    );
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
              Reset your <span className="text-primary">password.</span>
            </h1>
            <p className="mt-5 leading-7 text-on-surface-variant">
              Choose a strong, unique password to keep your workspace secure.
            </p>
          </div>
          <p className="font-mono text-xs text-on-surface-variant">CYBERSHIELD AI · STATIC PRODUCT DEMO</p>
        </div>
      </section>

      <section className="flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          <Link to="/login" className="mb-10 inline-flex lg:hidden" aria-label="CyberShield — Go to dashboard">
            <BrandLogo className="h-8 w-auto max-w-[180px]" />
          </Link>
          <p className="eyebrow mb-3">New credentials</p>
          <h2 className="font-display text-3xl font-bold">Set a new password</h2>
          <p className="mt-3 text-sm leading-6 text-on-surface-variant">
            Enter your new password below. You will be redirected to your dashboard after a successful update.
          </p>

          {!hasSession && !success && (
            <div className="mt-6 flex items-start gap-2 rounded border border-warning/30 bg-warning/10 px-4 py-3 text-sm text-warning">
              <AlertCircle size={16} className="mt-0.5 shrink-0" />
              <span>Recovery session not found. The reset link may be invalid or expired. Please request a new link from the login page.</span>
            </div>
          )}

          {error && (
            <p className="mt-4 flex items-start gap-2 rounded border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger">
              <AlertCircle size={16} className="mt-0.5 shrink-0" /> <span>{error}</span>
            </p>
          )}

          {success && (
            <p className="mt-4 flex items-start gap-2 rounded border border-success/30 bg-success/10 px-4 py-3 text-sm text-success">
              <CheckCircle size={16} className="mt-0.5 shrink-0" /> <span>Password updated successfully! Redirecting to dashboard…</span>
            </p>
          )}

          <form className="mt-8 grid gap-5" onSubmit={handleSubmit} noValidate>
            <PasswordInput
              label="New password"
              placeholder="••••••••••••"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
              required
              disabled={submitting || success}
              maxLength={4096}
            />
            <PasswordInput
              label="Confirm new password"
              placeholder="••••••••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              autoComplete="new-password"
              required
              disabled={submitting || success}
              maxLength={4096}
            />

            <Button type="submit" className="mt-2 w-full" disabled={submitting || success || !hasSession}>
              {submitting ? (
                <>
                  <Loader2 size={16} className="animate-spin mr-2" /> Updating…
                </>
              ) : (
                'Update password'
              )}
            </Button>
          </form>

          <p className="mt-6 text-center text-sm text-on-surface-variant">
            Remembered your password?{' '}
            <Link className="font-semibold text-primary hover:underline" to="/login">
              Back to sign in
            </Link>
          </p>
        </div>
      </section>
    </main>
  );
}
