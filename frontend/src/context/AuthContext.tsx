import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { Session, User } from '@supabase/supabase-js';
import { apiClient } from '../services/apiClient';
import { supabase } from '../services/supabaseClient';
import type { AuthProvider as SupabaseAuthProvider, AuthSession, AuthUser, UserProfile } from '../types';

export interface AuthContextValue {
  readonly user: AuthUser | null;
  readonly session: AuthSession | null;
  readonly profile: UserProfile | null;
  readonly initializing: boolean;
  readonly signIn: (email: string, password: string) => Promise<void>;
  readonly signUp: (email: string, password: string, fullName?: string) => Promise<boolean>;
  readonly signOut: () => Promise<void>;
}

function mapUser(authUser: User | null): AuthUser | null {
  if (authUser === null) return null;
  const metadata = authUser.user_metadata ?? {};
  return {
    id: authUser.id,
    email: authUser.email ?? null,
    name: typeof metadata.full_name === 'string' ? metadata.full_name : (authUser.email ?? null),
    avatarUrl: typeof metadata.avatar_url === 'string' ? metadata.avatar_url : null,
    createdAt: authUser.created_at ?? null,
    provider: (authUser.app_metadata?.provider as SupabaseAuthProvider | undefined) ?? null,
  };
}

function mapSession(authSession: Session | null): AuthSession | null {
  if (authSession === null) return null;
  return {
    accessToken: authSession.access_token,
    refreshToken: authSession.refresh_token ?? null,
    expiresAt: authSession.expires_at ?? null,
    user: mapUser(authSession.user),
  };
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { readonly children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [session, setSession] = useState<AuthSession | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [initializing, setInitializing] = useState(true);

  useEffect(() => {
    supabase.auth
      .getSession()
      .then(({ data }) => {
        setSession(mapSession(data.session));
        setUser(mapUser(data.session?.user ?? null));
      })
      .catch(() => {})
      .finally(() => setInitializing(false));
  }, []);

  useEffect(() => {
    const { data: listener } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(mapSession(nextSession));
      setUser(mapUser(nextSession?.user ?? null));
    });
    return () => { listener.subscription.unsubscribe(); };
  }, []);

  useEffect(() => {
    if (session === null) {
      setProfile(null);
      return;
    }
    let cancelled = false;
    apiClient
      .get<UserProfile>('/auth/me')
      .then((nextProfile) => { if (!cancelled) setProfile(nextProfile); })
      .catch(() => { if (!cancelled) setProfile(null); });
    return () => { cancelled = true; };
  }, [session?.accessToken]);

  const signIn = useCallback(async (email: string, password: string) => {
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw new Error(error.message);
  }, []);

  const signUp = useCallback(async (email: string, password: string, fullName?: string): Promise<boolean> => {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: fullName === undefined ? undefined : { data: { full_name: fullName } },
    });
    if (error) throw new Error(error.message);
    return data.session !== null;
  }, []);

  const signOut = useCallback(async () => {
    const { error } = await supabase.auth.signOut();
    if (error) throw new Error(error.message);
  }, []);

  const value = useMemo<AuthContextValue>(() => ({
    user,
    session,
    profile,
    initializing,
    signIn,
    signUp,
    signOut,
  }), [user, session, profile, initializing, signIn, signUp, signOut]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
