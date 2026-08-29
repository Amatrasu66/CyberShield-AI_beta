import { LogOut } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { navigation, userNav } from '../data/mockData';
import { useAuth } from '../context/AuthContext';
import { Button } from './ui';
import { BrandLockup } from './BrandLogo';
import { cn } from '../utils/cn';
import { getDisplayName, getInitials } from '../utils/getInitials';

export interface SidebarProps {
  readonly open: boolean;
  readonly onNavigate: () => void;
}

export function Sidebar({ open, onNavigate }: SidebarProps) {
  const location = useLocation();
  const { user, profile, signOut } = useAuth();

  // Dynamic identity — source of truth is AuthContext
  const displayName = getDisplayName(profile?.full_name ?? null, user?.name ?? null, user?.email ?? null);
  const email = user?.email ?? null;
  const role = typeof profile?.role === 'string' && profile.role.trim().length > 0 ? profile.role.trim() : null;
  const initials = getInitials(displayName || email, email);

  const subtitle = email ?? role ?? '—';
  const shownName = displayName || (email ? email.split('@')[0] ?? email : '—');

  const group = (items: typeof navigation) =>
    items.map(({ label, to, icon: Icon }) => (
      <Link
        key={to}
        to={to}
        onClick={onNavigate}
        className={cn(
          'group flex items-center gap-3 rounded px-3 py-2.5 text-sm transition',
          location.pathname === to
            ? 'bg-primary/10 text-primary shadow-[inset_2px_0_0_0_currentColor]'
            : 'text-on-surface-variant hover:bg-surface-high hover:text-on-surface',
        )}
      >
        <Icon size={18} />
        <span>{label}</span>
      </Link>
    ));

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-40 flex w-[280px] flex-col border-r bg-surface-lowest transition-transform lg:static lg:translate-x-0',
        open ? 'translate-x-0' : '-translate-x-full',
      )}
    >
      <Link
        to="/dashboard"
        className="flex items-center border-b px-5 py-4 sm:px-6 sm:py-5"
        onClick={onNavigate}
        aria-label="CyberShield — Go to dashboard"
      >
        <BrandLockup size="sidebar" />
      </Link>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-5">
        {group(navigation)}
        <p className="eyebrow px-3 pb-2 pt-6">Workspace</p>
        {group(userNav as typeof navigation)}
      </nav>

      <div className="border-t p-4">
        <div className="flex items-center gap-3 rounded bg-surface-container p-3">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-full bg-secondary/15 font-mono text-sm text-secondary">
            {initials}
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold">{shownName}</p>
            <p className="truncate text-xs text-on-surface-variant" title={subtitle}>
              {subtitle}
            </p>
            {role && role !== subtitle && (
              <p className="truncate text-[11px] capitalize text-on-surface-variant/80">{role}</p>
            )}
            {!role && !email && (
              <p className="truncate text-xs text-on-surface-variant">—</p>
            )}
          </div>
        </div>
        <Button
          variant="ghost"
          className="mt-3 w-full"
          onClick={() => {
            void signOut();
          }}
        >
          <LogOut size={16} /> Sign out
        </Button>
      </div>
    </aside>
  );
}
