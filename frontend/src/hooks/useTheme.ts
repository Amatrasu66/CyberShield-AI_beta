import { useCallback, useEffect, useState } from 'react';

export type ThemePreference = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'cybershield-theme';

function getStoredPreference(): ThemePreference {
  if (typeof window === 'undefined') return 'dark';
  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (raw === 'light' || raw === 'dark' || raw === 'system') return raw;
  return 'dark';
}

function resolveEffective(pref: ThemePreference): 'light' | 'dark' {
  if (pref !== 'system') return pref;
  if (typeof window === 'undefined') return 'dark';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(effective: 'light' | 'dark') {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  if (effective === 'dark') {
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
  }
}

export function useTheme() {
  const [preference, setPreferenceState] = useState<ThemePreference>(() => getStoredPreference());
  const [effective, setEffective] = useState<'light' | 'dark'>(() => resolveEffective(getStoredPreference()));

  useEffect(() => {
    const eff = resolveEffective(preference);
    setEffective(eff);
    applyTheme(eff);
    window.localStorage.setItem(STORAGE_KEY, preference);
  }, [preference]);

  // Keep in sync with system changes when preference is 'system'
  useEffect(() => {
    if (preference !== 'system') return;
    const mql = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = () => {
      const eff = mql.matches ? 'dark' : 'light';
      setEffective(eff);
      applyTheme(eff);
    };
    // Initial sync
    handler();
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, [preference]);

  // Apply stored theme on first mount even before preference state settles (handles reload)
  useEffect(() => {
    const stored = getStoredPreference();
    applyTheme(resolveEffective(stored));
  }, []);

  const setPreference = useCallback((next: ThemePreference) => {
    setPreferenceState(next);
  }, []);

  return { preference, effective, setPreference } as const;
}

/** Initialize theme from localStorage without React state — call once at app boot. */
export function initTheme(): void {
  if (typeof window === 'undefined') return;
  const stored = getStoredPreference();
  applyTheme(resolveEffective(stored));
}
