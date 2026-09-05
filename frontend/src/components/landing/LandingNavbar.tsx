import { useState, type ReactNode } from 'react';
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

  function closeMobile() {
    setMobileOpen(false);
  }

  return (
    <header
      data-testid="landing-navbar"
      className="sticky top-0 z-50 border-b border-border/60 bg-background/85 backdrop-blur"
    >
      <nav
        aria-label="Primary"
        className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-6 px-4 sm:px-6 lg:px-8"
      >
        <Link to="/" aria-label="CyberShield — Home" className="shrink-0">
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
            className="overflow-hidden border-t border-border/60 lg:hidden"
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
