import { useEffect, useMemo, useState } from 'react';
import { KeyRound, Save, ShieldAlert, UserRound } from 'lucide-react';
import { PageHeader } from '../components/PageHeader';
import { Badge, Button, Card, TextInput } from '../components/ui';
import { useAuth } from '../context/AuthContext';
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

  // Sync draft when authoritative name changes (but not while user is typing unsaved changes — only on initial load / profile change)
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

export interface SettingsPageProps { readonly notifications?: boolean; }
export function SettingsPage({ notifications = true }: SettingsPageProps) { return <><PageHeader eyebrow="Workspace" title="Settings" description="Configure display preferences and demo security notifications." /><div className="max-w-3xl space-y-5"><Card className="p-6"><h2 className="font-display text-lg font-semibold">Notification preferences</h2>{['Critical threat alerts', 'Weekly security digest', 'Scan completion updates'].map((label, index) => <label className="mt-5 flex items-center justify-between" key={label}><span><span className="block text-sm font-medium">{label}</span><span className="mt-1 block text-xs text-on-surface-variant">Static preference control</span></span><input className="h-5 w-5 accent-primary" defaultChecked={notifications && index !== 2} type="checkbox" /></label>)}</Card><Card className="p-6"><div className="flex items-start gap-3"><ShieldAlert className="mt-0.5 text-warning" /><div><h2 className="font-display text-lg font-semibold">Demo environment</h2><p className="mt-2 text-sm leading-6 text-on-surface-variant">This Phase 1 frontend intentionally uses no API connection, authentication, or saved preferences.</p></div></div></Card></div></>; }

export interface NotFoundPageProps { readonly message?: string; }
export function NotFoundPage({ message = 'The security console page you requested could not be located.' }: NotFoundPageProps) { return <div className="flex min-h-[70vh] items-center justify-center"><div className="max-w-lg text-center"><p className="font-mono text-8xl font-bold text-primary/30">404</p><h1 className="mt-4 font-display text-3xl font-bold">Signal lost</h1><p className="mt-3 text-on-surface-variant">{message}</p><Button className="mt-7" onClick={() => window.history.back()}><KeyRound size={16} /> Return to safety</Button></div></div>; }
