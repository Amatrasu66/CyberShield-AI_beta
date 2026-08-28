import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Loader2, AlertCircle } from 'lucide-react';
import { supabase } from '../services/supabaseClient';

export function AuthCallbackPage() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function handleCallback() {
      try {
        // Handle PKCE code exchange if present (Supabase will also handle hash fragments via detectSessionInUrl)
        const url = new URL(window.location.href);
        const code = url.searchParams.get('code');
        const errorParam = url.searchParams.get('error');
        const errorDescription = url.searchParams.get('error_description');

        if (errorParam) {
          throw new Error(errorDescription ?? 'Authentication failed. The confirmation link is invalid or has expired.');
        }

        if (code) {
          const { error: exchangeError } = await supabase.auth.exchangeCodeForSession(window.location.href);
          if (exchangeError) throw new Error(exchangeError.message);
        }

        // With detectSessionInUrl:true, Supabase also parses hash fragments automatically.
        // Ensure session is established
        const { data, error: sessionError } = await supabase.auth.getSession();
        if (sessionError) throw new Error(sessionError.message);

        if (!data.session) {
          // Wait briefly for onAuthStateChange to establish session via hash parsing
          await new Promise((r) => setTimeout(r, 500));
          const { data: retry } = await supabase.auth.getSession();
          if (!retry.session) {
            throw new Error('No active session found. The confirmation link may be invalid or expired. Please try signing in.');
          }
        }

        if (!cancelled) {
          navigate('/dashboard', { replace: true });
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'An unexpected error occurred during confirmation.');
        }
      }
    }

    void handleCallback();
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  if (error) {
    return (
      <main className="grid min-h-screen place-items-center bg-background p-6">
        <div className="w-full max-w-md rounded border bg-surface p-6 text-center">
          <div className="mx-auto grid h-12 w-12 place-items-center rounded-full bg-danger/15 text-danger">
            <AlertCircle size={24} />
          </div>
          <h1 className="mt-4 font-display text-xl font-bold">Confirmation failed</h1>
          <p className="mt-2 text-sm leading-6 text-on-surface-variant">{error}</p>
          <button
            onClick={() => navigate('/login', { replace: true })}
            className="mt-6 inline-flex h-10 items-center justify-center rounded bg-primary px-4 text-sm font-semibold text-primary-foreground hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-primary/60"
          >
            Back to sign in
          </button>
        </div>
      </main>
    );
  }

  return (
    <main className="grid min-h-screen place-items-center bg-background p-6">
      <div className="flex flex-col items-center gap-4">
        <span className="grid h-12 w-12 animate-pulse place-items-center rounded bg-primary text-primary-foreground">
          <ShieldCheck size={22} />
        </span>
        <p className="flex items-center gap-2 text-sm text-on-surface-variant">
          <Loader2 size={16} className="animate-spin" /> Confirming your email…
        </p>
      </div>
    </main>
  );
}
