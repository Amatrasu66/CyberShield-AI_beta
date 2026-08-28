import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertTriangle, CheckCircle, KeyRound, LogOut, Monitor, Moon, Save, ShieldAlert, ShieldCheck, Sun, UserRound } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card, TextInput } from '../components/ui';
import { PasswordInput } from '../components/PasswordInput';
import { useAuth } from '../context/AuthContext';
import { useTheme, type ThemePreference } from '../hooks/useTheme';
import { ApiClientError } from '../services/apiClient';

function formatCreatedDate(iso: string | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return new Intl.DateTimeFormat('en-US', { month: 'long', day: 'numeric', year: 'numeric' }).format(d);
}

function resolveFullName(profileFullName: string | null, userName: string | null, email: string | null): string {
  if (profileFullName && profileFullName.trim().length > 0) return profileFullName.trim();
  if (userName && userName.trim().length > 0) return userName.trim();
  if (email && email.includes('@')) return email.split('@')[0] ?? email;
  if (email) return email;
  return '';
}

export interface ProfilePageProps { readonly editable?: boolean; }
export function ProfilePage({ editable = true }: ProfilePageProps) {
  const { user, profile, initializing, updateProfile } = useAuth();

  const email = user?.email ?? null;
  const role = profile?.role ?? null;
  const createdAtIso = user?.createdAt ?? profile?.created_at ?? null;

  const displayName = useMemo(
    () => resolveFullName(profile?.full_name ?? null, user?.name ?? null, email),
    [profile?.full_name, user?.name, email],
  );

  const initials = useMemo(() => {
    const base = displayName.trim() || email || 'U';
    const parts = base.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return base.slice(0, 2).toUpperCase() || 'U';
  }, [displayName, email]);

  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const authoritativeName = profile?.full_name ?? user?.name ?? '';
  useEffect(() => {
    setDraft(authoritativeName);
  }, [authoritativeName]);

  const trimmed = draft.trim();
  const hasChanged = trimmed !== (authoritativeName.trim());
  const validationError = useMemo(() => {
    if (trimmed.length === 0) return 'Full name must not be empty';
    if (trimmed.length > 100) return 'Full name must be at most 100 characters';
    if (/[\x00-\x1F]/.test(trimmed)) return 'Full name contains invalid characters';
    return null;
  }, [trimmed]);

  const createdLabel = formatCreatedDate(createdAtIso);

  if (initializing) {
    return (
      <>
        <PageHeader eyebrow="Account" title="User Profile" description="Manage the workspace identity shown across CyberShield AI." />
        <div className="max-w-4xl">
          <Card className="p-6">
            <p className="animate-pulse text-sm text-on-surface-variant">Loading profile…</p>
          </Card>
        </div>
      </>
    );
  }

  const handleSave = async () => {
    setError(null);
    setSuccess(null);
    if (validationError) {
      setError(validationError);
      return;
    }
    setSaving(true);
    try {
      await updateProfile(trimmed);
      setSuccess('Profile updated successfully');
    } catch (e) {
      const msg = e instanceof ApiClientError ? e.message : e instanceof Error ? e.message : 'Failed to update profile';
      setError(msg);
    } finally {
      setSaving(false);
    }
  };

  const saveDisabled = saving || !hasChanged || validationError !== null || !editable;

  return (
    <>
      <PageHeader eyebrow="Account" title="User Profile" description="Manage the workspace identity shown across CyberShield AI." />
      <div className="grid max-w-4xl gap-5 md:grid-cols-[0.8fr_1.2fr]">
        <Card className="flex flex-col items-center p-6 text-center">
          <span className="grid h-20 w-20 place-items-center rounded-full bg-secondary/15 text-secondary">
            <UserRound size={35} />
          </span>
          <h2 className="mt-4 font-display text-xl font-semibold">{displayName || 'Unnamed user'}</h2>
          <p className="mt-1 text-sm text-on-surface-variant">{email ?? 'No email'}</p>
          <Badge tone="success">{role ?? 'Student'}</Badge>
          <dl className="mt-4 w-full space-y-2 border-t pt-4 text-left text-sm">
            <div className="flex justify-between gap-2">
              <dt className="text-on-surface-variant">Role</dt>
              <dd className="font-medium">{role ?? '—'}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-on-surface-variant">Member since</dt>
              <dd className="font-medium">{createdLabel}</dd>
            </div>
          </dl>
          <span className="mt-3 grid h-9 w-9 place-items-center rounded-full bg-primary/10 font-mono text-xs text-primary" aria-label="Initials">
            {initials}
          </span>
        </Card>

        <Card className="p-6">
          <h2 className="font-display text-lg font-semibold">Personal information</h2>
          <p className="mt-1 text-xs text-on-surface-variant">Email and role are managed by your workspace administrator.</p>

          {error && (
            <div role="alert" className="mt-4 rounded border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
              {error}
            </div>
          )}
          {success && (
            <div role="status" className="mt-4 rounded border border-success/30 bg-success/10 px-3 py-2 text-sm text-success">
              {success}
            </div>
          )}

          <div className="mt-5 grid gap-4 sm:grid-cols-2">
            <div>
              <TextInput
                label="Full name"
                value={draft}
                onChange={(e) => {
                  setDraft(e.target.value);
                  if (success) setSuccess(null);
                  if (error) setError(null);
                }}
                placeholder="Your full name"
                disabled={saving || !editable}
                aria-invalid={validationError !== null}
              />
              {validationError && hasChanged && (
                <p className="mt-1 text-xs text-danger">{validationError}</p>
              )}
              <p className="mt-1 text-xs text-on-surface-variant">{trimmed.length}/100</p>
            </div>

            <div>
              <TextInput label="Role" value={role ?? '—'} readOnly disabled aria-describedby="role-help" />
              <p id="role-help" className="mt-1 text-xs text-on-surface-variant">Contact an administrator to change your role.</p>
            </div>

            <div className="sm:col-span-2">
              <TextInput label="Email address" value={email ?? ''} readOnly disabled />
              <p className="mt-1 text-xs text-on-surface-variant">Email is managed via Supabase Auth and requires confirmation to change — left read-only.</p>
            </div>

            <div className="sm:col-span-2">
              <TextInput label="Account created" value={createdLabel} readOnly disabled />
            </div>
          </div>

          {editable && (
            <Button className="mt-6" onClick={handleSave} disabled={saveDisabled} aria-busy={saving}>
              <Save size={16} />
              {saving ? 'Saving…' : 'Save changes'}
            </Button>
          )}
        </Card>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Settings — Phase 3A-3
// ---------------------------------------------------------------------------

const NOTIF_STORAGE_KEY = 'cybershield-notif-prefs';
type NotifPrefs = { critical: boolean; digest: boolean; scans: boolean };
const DEFAULT_NOTIF_PREFS: NotifPrefs = { critical: true, digest: true, scans: false };

function loadNotifPrefs(): NotifPrefs {
  try {
    const raw = window.localStorage.getItem(NOTIF_STORAGE_KEY);
    if (!raw) return DEFAULT_NOTIF_PREFS;
    const parsed = JSON.parse(raw) as Partial<NotifPrefs>;
    return {
      critical: typeof parsed.critical === 'boolean' ? parsed.critical : DEFAULT_NOTIF_PREFS.critical,
      digest: typeof parsed.digest === 'boolean' ? parsed.digest : DEFAULT_NOTIF_PREFS.digest,
      scans: typeof parsed.scans === 'boolean' ? parsed.scans : DEFAULT_NOTIF_PREFS.scans,
    };
  } catch {
    return DEFAULT_NOTIF_PREFS;
  }
}

function sanitizePasswordError(err: unknown): string {
  if (err instanceof Error) {
    const msg = err.message.toLowerCase();
    // Known Supabase weak-password or same-password messages are safe to surface lightly
    if (msg.includes('password should be at least') || msg.includes('weak') || msg.includes('same password')) {
      return err.message;
    }
    // Avoid leaking raw provider internals
    if (msg.includes('supabase') || msg.includes('auth') || msg.includes('jwt') || msg.includes('token') || msg.includes('database')) {
      return 'Unable to update your password. Please try again.';
    }
    // Short, user-friendly fallback for other messages
    if (err.message.length < 120) return err.message;
  }
  return 'Unable to update your password. Please try again.';
}

export function SettingsPage() {
  const { user, profile, session, initializing, signOut, updatePassword } = useAuth();
  const { preference: themePref, setPreference: setThemePref } = useTheme();

  const email = user?.email ?? null;
  const role = profile?.role ?? null;
  const displayName = useMemo(
    () => resolveFullName(profile?.full_name ?? null, user?.name ?? null, email),
    [profile?.full_name, user?.name, email],
  );

  // Password form state
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwError, setPwError] = useState<string | null>(null);
  const [pwSuccess, setPwSuccess] = useState<string | null>(null);
  const [pwSubmitting, setPwSubmitting] = useState(false);

  // Notification local prefs
  const [notifPrefs, setNotifPrefs] = useState<NotifPrefs>(() => {
    try {
      return loadNotifPrefs();
    } catch {
      return DEFAULT_NOTIF_PREFS;
    }
  });
  useEffect(() => {
    try {
      window.localStorage.setItem(NOTIF_STORAGE_KEY, JSON.stringify(notifPrefs));
    } catch {
      // ignore quota errors
    }
  }, [notifPrefs]);

  const [signingOut, setSigningOut] = useState(false);

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwError(null);
    setPwSuccess(null);
    if (newPassword.length < 8) {
      setPwError('Password must be at least 8 characters.');
      return;
    }
    if (newPassword.length > 4096) {
      setPwError('Password is too long.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwError('Passwords do not match.');
      return;
    }
    setPwSubmitting(true);
    try {
      await updatePassword(newPassword);
      setPwSuccess('Password updated successfully.');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setPwError(sanitizePasswordError(err));
    } finally {
      setPwSubmitting(false);
    }
  };

  const handleSignOut = async () => {
    setSigningOut(true);
    try {
      await signOut();
    } catch {
      setSigningOut(false);
    }
  };

  if (initializing) {
    return (
      <>
        <PageHeader eyebrow="Workspace" title="Settings" description="Manage your account, appearance, and security preferences." />
        <div className="max-w-3xl">
          <Card className="p-6">
            <p className="animate-pulse text-sm text-on-surface-variant">Loading settings…</p>
          </Card>
        </div>
      </>
    );
  }

  const sessionActive = session !== null;
  const providerLabel = user?.provider ?? 'email';

  return (
    <>
      <PageHeader eyebrow="Workspace" title="Settings" description="Manage your account, appearance, and security preferences." />
      <div className="max-w-3xl space-y-5">
        {/* A. Account */}
        <Card className="p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="font-display text-lg font-semibold">Account</h2>
              <p className="mt-1 text-xs text-on-surface-variant">Your authenticated identity. Email and role are read-only.</p>
            </div>
            <Link to="/profile" className="inline-flex h-8 items-center rounded border px-3 text-xs font-semibold text-on-surface-variant hover:bg-surface-high hover:text-on-surface">
              Edit profile
            </Link>
          </div>
          <div className="mt-5 grid gap-4 sm:grid-cols-2">
            <TextInput label="Full name" value={displayName || '—'} readOnly disabled />
            <TextInput label="Role" value={role ?? '—'} readOnly disabled />
            <div className="sm:col-span-2">
              <TextInput label="Email address" value={email ?? '—'} readOnly disabled />
              <p className="mt-1 text-xs text-on-surface-variant">Email is managed via Supabase Auth — read-only here. Profile name stays in sync with the Profile page.</p>
            </div>
          </div>
        </Card>

        {/* B. Appearance */}
        <Card className="p-6">
          <h2 className="font-display text-lg font-semibold">Appearance</h2>
          <p className="mt-1 text-xs text-on-surface-variant">Choose how CyberShield AI looks in your browser. Preference is saved locally and persists across reloads.</p>
          <div className="mt-4 grid grid-cols-3 gap-2">
            {([
              { value: 'light' as ThemePreference, label: 'Light', icon: Sun },
              { value: 'dark' as ThemePreference, label: 'Dark', icon: Moon },
              { value: 'system' as ThemePreference, label: 'System', icon: Monitor },
            ] as const).map(({ value, label, icon: Icon }) => {
              const active = themePref === value;
              return (
                <button
                  key={value}
                  type="button"
                  onClick={() => setThemePref(value)}
                  className={
                    'flex flex-col items-center gap-2 rounded border px-3 py-4 text-sm font-medium transition ' +
                    (active ? 'border-primary bg-primary/10 text-primary' : 'border-outline-variant bg-surface-low text-on-surface-variant hover:bg-surface-high hover:text-on-surface')
                  }
                  aria-pressed={active}
                >
                  <Icon size={18} />
                  {label}
                </button>
              );
            })}
          </div>
          <p className="mt-3 text-xs text-on-surface-variant">System follows your OS setting. Stored as <span className="font-mono text-on-surface">{themePref}</span> in local storage — no backend setting.</p>
        </Card>

        {/* C. Notifications */}
        <Card className="p-6">
          <h2 className="font-display text-lg font-semibold">Notifications</h2>
          <p className="mt-1 text-xs text-on-surface-variant">These are local preferences only. Delivery requires future backend infrastructure.</p>
          <div className="mt-4 rounded border border-warning/20 bg-warning/10 px-3 py-2 text-xs leading-5 text-warning">
            <span className="font-semibold">Coming soon:</span> notification delivery is not yet wired to a backend. Toggles below are stored locally in your browser.
          </div>
          <div className="mt-4 space-y-4">
            <label className="flex items-center justify-between gap-4">
              <span>
                <span className="block text-sm font-medium">Critical threat alerts</span>
                <span className="mt-1 block text-xs text-on-surface-variant">High-severity findings — local preference only</span>
              </span>
              <input
                type="checkbox"
                className="h-5 w-5 accent-primary"
                checked={notifPrefs.critical}
                onChange={(e) => setNotifPrefs((p) => ({ ...p, critical: e.target.checked }))}
                aria-label="Critical threat alerts"
              />
            </label>
            <label className="flex items-center justify-between gap-4">
              <span>
                <span className="block text-sm font-medium">Weekly security digest</span>
                <span className="mt-1 block text-xs text-on-surface-variant">Summary of recent activity — local preference only</span>
              </span>
              <input
                type="checkbox"
                className="h-5 w-5 accent-primary"
                checked={notifPrefs.digest}
                onChange={(e) => setNotifPrefs((p) => ({ ...p, digest: e.target.checked }))}
                aria-label="Weekly security digest"
              />
            </label>
            <label className="flex items-center justify-between gap-4">
              <span>
                <span className="block text-sm font-medium">Scan completion updates</span>
                <span className="mt-1 block text-xs text-on-surface-variant">When a scan finishes — local preference only</span>
              </span>
              <input
                type="checkbox"
                className="h-5 w-5 accent-primary"
                checked={notifPrefs.scans}
                onChange={(e) => setNotifPrefs((p) => ({ ...p, scans: e.target.checked }))}
                aria-label="Scan completion updates"
              />
            </label>
          </div>
        </Card>

        {/* D. Security */}
        <Card className="p-6">
          <h2 className="font-display text-lg font-semibold">Security</h2>
          <p className="mt-1 text-xs text-on-surface-variant">Update your password and review session information. Password changes use Supabase Auth directly.</p>

          {/* Password change */}
          <form onSubmit={handlePasswordChange} noValidate className="mt-5 grid gap-4">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <KeyRound size={16} className="text-primary" /> Change password
            </h3>
            {pwError && (
              <div role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-sm text-danger">
                {pwError}
              </div>
            )}
            {pwSuccess && (
              <div role="status" className="flex items-center gap-2 rounded border border-success/30 bg-success/10 px-3 py-2 text-sm text-success">
                <CheckCircle size={16} /> {pwSuccess}
              </div>
            )}
            <PasswordInput
              label="New password"
              placeholder="••••••••••••"
              value={newPassword}
              onChange={(e) => {
                setNewPassword(e.target.value);
                if (pwError) setPwError(null);
                if (pwSuccess) setPwSuccess(null);
              }}
              autoComplete="new-password"
              disabled={pwSubmitting}
              maxLength={4096}
              required
            />
            <PasswordInput
              label="Confirm new password"
              placeholder="••••••••••••"
              value={confirmPassword}
              onChange={(e) => {
                setConfirmPassword(e.target.value);
                if (pwError) setPwError(null);
                if (pwSuccess) setPwSuccess(null);
              }}
              autoComplete="new-password"
              disabled={pwSubmitting}
              maxLength={4096}
              required
            />
            <p className="text-xs text-on-surface-variant">Minimum 8 characters. Password is sent only to Supabase Auth — never to our Flask backend and never stored in local storage.</p>
            <div>
              <Button type="submit" disabled={pwSubmitting} aria-busy={pwSubmitting}>
                {pwSubmitting ? 'Updating…' : 'Update password'}
              </Button>
            </div>
          </form>

          {/* Session info */}
          <div className="mt-6 border-t pt-6">
            <h3 className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck size={16} className="text-success" /> Session
            </h3>
            <dl className="mt-3 grid gap-2 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-on-surface-variant">Signed in as</dt>
                <dd className="font-medium">{email ?? '—'}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-on-surface-variant">Status</dt>
                <dd className="font-medium">{sessionActive ? 'Active session' : 'No active session'}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-on-surface-variant">Provider</dt>
                <dd className="font-medium">{providerLabel}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-on-surface-variant">Member since</dt>
                <dd className="font-medium">{formatCreatedDate(user?.createdAt ?? profile?.created_at ?? null)}</dd>
              </div>
            </dl>
            <p className="mt-3 text-xs text-on-surface-variant">Tokens and credentials are never displayed here.</p>
          </div>

          {/* Sign out */}
          <div className="mt-6 border-t pt-6">
            <Button variant="secondary" onClick={handleSignOut} disabled={signingOut} aria-busy={signingOut}>
              <LogOut size={16} />
              {signingOut ? 'Signing out…' : 'Sign out'}
            </Button>
            <p className="mt-2 text-xs text-on-surface-variant">You will be returned to the login page. Protected routes require authentication.</p>
          </div>
        </Card>

        {/* E. Danger Zone */}
        <Card className="p-6 border-danger/30">
          <h2 className="flex items-center gap-2 font-display text-lg font-semibold text-danger">
            <AlertTriangle size={18} /> Danger Zone
          </h2>
          <p className="mt-1 text-xs text-on-surface-variant">Irreversible actions are isolated here.</p>
          <div className="mt-4 rounded border border-danger/20 bg-danger/10 p-4">
            <h3 className="text-sm font-semibold text-danger">Delete account</h3>
            <p className="mt-1 text-xs leading-5 text-on-surface-variant">Account deletion is not yet available. It requires secure Supabase handling and proper authorization — planned for a future phase.</p>
            <Button variant="danger" className="mt-3" disabled aria-disabled="true" title="Account deletion is not yet available">
              Delete account — unavailable
            </Button>
          </div>
          <div className="mt-4 flex items-start gap-3 rounded border border-outline-variant bg-surface-low p-4">
            <ShieldAlert className="mt-0.5 text-warning" size={18} />
            <div>
              <h3 className="text-sm font-semibold">Safe action</h3>
              <p className="mt-1 text-xs leading-5 text-on-surface-variant">Need to step away? Sign out securely.</p>
              <Button variant="ghost" className="mt-3 border" onClick={handleSignOut} disabled={signingOut}>
                <LogOut size={16} /> Sign out
              </Button>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}

export interface NotFoundPageProps { readonly message?: string; }
export function NotFoundPage({ message = 'The security console page you requested could not be located.' }: NotFoundPageProps) { return <div className="flex min-h-[70vh] items-center justify-center"><div className="max-w-lg text-center"><p className="font-mono text-8xl font-bold text-primary/30">404</p><h1 className="mt-4 font-display text-3xl font-bold">Signal lost</h1><p className="mt-3 text-on-surface-variant">{message}</p><Button className="mt-7" onClick={() => window.history.back()}><KeyRound size={16} /> Return to safety</Button></div></div>; }
