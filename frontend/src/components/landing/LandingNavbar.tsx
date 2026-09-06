import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import {
  BarChart3,
  Bug,
  FileText,
  GraduationCap,
  KeyRound,
  MailWarning,
  Menu,
  ScanSearch,
  ShieldCheck,
  Terminal,
  X,
} from 'lucide-react';
import { BrandLockup } from '../BrandLogo';
import { Button } from '../ui';
import { MotionNavigationMenu, type MotionNavigationEntry } from '../ui/motion-navigation-menu';
import { cn } from '../../utils/cn';

const CAPABILITIES: MotionNavigationEntry['links'] = [
  {
    label: 'Website Security Scanner',
    to: '/website-scanner',
    description: 'Headers, TLS posture and configuration signals.',
    icon: ScanSearch,
  },
  {
    label: 'Phishing Detection',
    to: '/phishing-detector',
    description: 'Language patterns and risk indicators in messages.',
    icon: MailWarning,
  },
  {
    label: 'Password Analysis',
    to: '/password-analyzer',
    description: 'Strength, entropy and exposure signals.',
    icon: KeyRound,
  },
  {
    label: 'Log Analysis',
    to: '/log-analyzer',
    description: 'Anomaly signals across pasted log lines.',
    icon: BarChart3,
  },
  {
    label: 'Port Scanner',
    to: '/port-scanner',
    description: 'TCP connect scans with service and banner detail.',
    icon: Terminal,
  },
  {
    label: 'SQL Playground',
    to: '/sql-playground',
    description: 'Guided scenarios in an isolated sandbox.',
    icon: Bug,
  },
  {
    label: 'Cryptography Lab',
    to: '/cryptography-lab',
    description: 'Browser-side hashing and encryption experiments.',
    icon: ShieldCheck,
  },
  {
    label: 'Security Reports',
    to: '/reports',
    description: 'PDF summaries generated from scan history.',
    icon: FileText,
  },
];

const ENTRIES: readonly MotionNavigationEntry[] = [
  { label: 'Capabilities', links: CAPABILITIES },
  { label: 'Workflow', to: '#workflow' },
  {
    label: 'Resources',
    links: [
      {
        label: 'Security Tutorials',
        to: '/tutorials',
        description: 'Guided lessons for each security tool.',
        icon: GraduationCap,
      },
    ],
  },
];

interface MobileLinkProps {
  readonly to: string;
  readonly onNavigate: () => void;
  readonly children: ReactNode;
  readonly className?: string;
}

function MobileLink({ to, onNavigate, children, className }: MobileLinkProps) {
  const classes = cn(
    'block rounded-lg px-3 py-2.5 text-sm text-on-surface-variant transition-colors hover:bg-surface-high/60 hover:text-on-surface',
    className,
  );
  if (to.startsWith('#')) {
    return (
      <a href={to} onClick={onNavigate} className={classes}>
        {children}
      </a>
    );
  }
  return (
    <Link to={to} onClick={onNavigate} className={classes}>
      {children}
    </Link>
  );
}

export function LandingNavbar() {
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  // Phase 7.3 — auto-hiding navbar: visible at top, slides away on scroll
  // down, returns on scroll up. Transform-only animation (no layout shift),
  // stays in the DOM for keyboard users (no display:none).
  const [hidden, setHidden] = useState(false);
  const lastScrollY = useRef(0);
  const ticking = useRef(false);

  function closeMobile() {
    setMobileOpen(false);
  }

  useEffect(() => {
    lastScrollY.current = window.scrollY || 0;
    const TOP_LOCK_PX = 24; // force visible near the top
    const HIDE_AFTER_PX = 120; // only hide after meaningful downward scroll
    const DEAD_ZONE_PX = 4; // ignore tiny/jittery movements

    const update = () => {
      ticking.current = false;
      const y = window.scrollY || 0;
      const prev = lastScrollY.current;
      const delta = y - prev;
      lastScrollY.current = y;
      if (y <= TOP_LOCK_PX) {
        setHidden(false);
        return;
      }
      if (Math.abs(delta) < DEAD_ZONE_PX) return;
      if (delta > 0 && y > HIDE_AFTER_PX) {
        setHidden(true);
      } else if (delta < 0) {
        setHidden(false);
      }
    };

    const onScroll = () => {
      if (!ticking.current) {
        ticking.current = true;
        window.requestAnimationFrame(update);
      }
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', onScroll);
    };
  }, []);

  // Keep the bar visible while the mobile menu is open or while keyboard
  // focus is inside the navigation (hidden state is purely visual).
  const visuallyHidden = hidden && !mobileOpen;

  return (
    <header
      data-testid="landing-navbar"
      onFocusCapture={() => setHidden(false)}
      className={cn(
        // Seamless floating navigation: no border, no divider, no shadow,
        // no card/glass/blur, no navbar background. Transparent so the page
        // background continues uninterrupted behind and around the content.
        // Only the content itself is visible. Auto-hide uses transform only.
        'fixed inset-x-0 top-0 z-50 border-0 bg-transparent shadow-none',
        'transition-transform duration-300 ease-out will-change-transform',
        visuallyHidden && '-translate-y-full',
      )}
    >
      <nav
        aria-label="Primary"
        className="mx-auto flex h-16 w-full max-w-6xl min-w-0 items-center justify-between gap-3 px-4 sm:gap-6 sm:px-6 lg:px-8"
      >
        <Link to="/" aria-label="CyberShield — Home" className="min-w-0 shrink">
          <BrandLockup size="sidebar" />
        </Link>

        <div className="hidden lg:block">
          <MotionNavigationMenu entries={ENTRIES} />
        </div>

        <div className="hidden shrink-0 items-center gap-2 lg:flex">
          <Link
            to="/login"
            className="rounded-full px-4 py-2 text-sm font-medium text-on-surface-variant transition-colors hover:text-on-surface"
          >
            Log in
          </Link>
          <Button type="button" onClick={() => void navigate('/register')} className="h-9">
            Get Started
          </Button>
        </div>

        <button
          type="button"
          aria-expanded={mobileOpen}
          aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
          onClick={() => setMobileOpen((open) => !open)}
          className="grid h-10 w-10 place-items-center rounded-lg text-on-surface-variant transition-colors hover:bg-surface-high/60 hover:text-on-surface lg:hidden"
        >
          {mobileOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </nav>

      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ type: 'spring', stiffness: 380, damping: 34 }}
            // Mobile panel: no top divider, no blur/shadow/border. Solid
            // page background (same as body) so items stay readable over the
            // hero while the closed navbar itself stays seamless/transparent.
            className="overflow-hidden bg-background lg:hidden"
          >
            <div className="max-h-[calc(100vh-4rem)] space-y-1 overflow-y-auto px-4 py-4 sm:px-6">
              <p className="eyebrow px-3 pb-1">Capabilities</p>
              {(CAPABILITIES ?? []).map((link) => (
                <MobileLink key={link.label} to={link.to} onNavigate={closeMobile}>
                  {link.label}
                </MobileLink>
              ))}
              <p className="eyebrow px-3 pb-1 pt-3">Explore</p>
              <MobileLink to="#workflow" onNavigate={closeMobile}>
                Workflow
              </MobileLink>
              <MobileLink to="/tutorials" onNavigate={closeMobile}>
                Security Tutorials
              </MobileLink>
              <div className="flex gap-2 border-t border-border/60 px-3 pb-1 pt-4">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    closeMobile();
                    void navigate('/login');
                  }}
                  className="flex-1"
                >
                  Log in
                </Button>
                <Button
                  type="button"
                  onClick={() => {
                    closeMobile();
                    void navigate('/register');
                  }}
                  className="flex-1"
                >
                  Get Started
                </Button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}
