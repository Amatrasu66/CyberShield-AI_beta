import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

function AuthLoadingScreen() {
  return <div className="grid min-h-screen place-items-center bg-background"><div className="flex flex-col items-center gap-4"><span className="grid h-12 w-12 animate-pulse place-items-center rounded bg-primary text-primary-foreground"><ShieldCheck size={22} /></span><p className="text-sm text-on-surface-variant">Loading workspace…</p></div></div>;
}

export interface AuthGuardProps { readonly children: ReactNode; }
export function RequireAuth({ children }: AuthGuardProps) {
  const { session, initializing } = useAuth();
  if (initializing) return <AuthLoadingScreen />;
  if (session === null) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export function RequireGuest({ children }: AuthGuardProps) {
  const { session, initializing } = useAuth();
  if (initializing) return <AuthLoadingScreen />;
  if (session !== null) return <Navigate to="/dashboard" replace />;
  return <>{children}</>;
}
