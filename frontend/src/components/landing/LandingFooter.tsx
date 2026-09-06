import { Link } from 'react-router-dom';
import { BrandLockup } from '../BrandLogo';
import { cn } from '../../utils/cn';

interface FooterLink {
  readonly label: string;
  readonly to: string;
}

const SECURITY_TOOLS: readonly FooterLink[] = [
  { label: 'Website Scanner', to: '/website-scanner' },
  { label: 'Phishing Detector', to: '/phishing-detector' },
  { label: 'Password Analyzer', to: '/password-analyzer' },
  { label: 'Log Analyzer', to: '/log-analyzer' },
  { label: 'Port Scanner', to: '/port-scanner' },
  { label: 'SQL Playground', to: '/sql-playground' },
  { label: 'Cryptography Lab', to: '/cryptography-lab' },
  { label: 'Security Reports', to: '/reports' },
];

const RESOURCES: readonly FooterLink[] = [
  { label: 'Security Tutorials', to: '/tutorials' },
  { label: 'Workflow', to: '#workflow' },
  { label: 'Capabilities', to: '#capabilities' },
];

const ACCOUNT: readonly FooterLink[] = [
  { label: 'Log in', to: '/login' },
  { label: 'Get Started', to: '/register' },
];

const linkClasses =
  'inline-block rounded py-1 text-sm text-on-surface-variant transition-colors hover:text-on-surface focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring';

function FooterLinkItem({ link }: { readonly link: FooterLink }) {
  if (link.to.startsWith('#')) {
    return (
      <a href={link.to} className={linkClasses}>
        {link.label}
      </a>
    );
  }
  return (
    <Link to={link.to} className={linkClasses}>
      {link.label}
    </Link>
  );
}

function FooterGroup({ title, links }: { readonly title: string; readonly links: readonly FooterLink[] }) {
  return (
    <nav aria-label={title}>
      <h3 className="eyebrow mb-4">{title}</h3>
      <ul className="space-y-1">
        {links.map((link) => (
          <li key={link.label}>
            <FooterLinkItem link={link} />
          </li>
        ))}
      </ul>
    </nav>
  );
}

/**
 * Landing footer adapted from the supplied 21st.dev large-name-footer:
 * brand block left, navigation columns right, oversized wordmark below.
 * Only real CyberShield destinations; no socials, legal, or invented routes.
 * Protected tool links are plain React Router links, so the existing
 * RequireAuth guard behavior is preserved for unauthenticated visitors.
 */
export function LandingFooter() {
  return (
    <footer data-testid="landing-footer" className="relative border-t border-border/40">
      <div className="mx-auto max-w-6xl px-4 pt-14 sm:px-6 lg:px-8 lg:pt-16">
        <div className="grid gap-10 lg:grid-cols-[0.9fr_1.1fr] lg:gap-14">
          <div>
            <BrandLockup size="sidebar" />
            <p className="mt-4 max-w-xs text-sm leading-6 text-on-surface-variant">
              Security intelligence for practical defense.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-8 sm:grid-cols-3">
            <FooterGroup title="Security Tools" links={SECURITY_TOOLS} />
            <FooterGroup title="Resources" links={RESOURCES} />
            <FooterGroup title="Account" links={ACCOUNT} />
          </div>
        </div>

        <div
          aria-hidden="true"
          className={cn(
            'select-none overflow-hidden pb-2 pt-10 text-center font-display font-bold uppercase leading-none tracking-tight text-on-surface/10 sm:pt-12',
            'text-[clamp(2.5rem,11vw,12rem)]',
          )}
        >
          Cybershield
        </div>

        <div className="flex flex-col gap-1 border-t border-border/40 py-6 text-xs text-on-surface-variant/70 sm:flex-row sm:items-center sm:justify-between">
          <p>© {new Date().getFullYear()} CyberShield</p>
          <p className="font-mono uppercase tracking-[0.14em]">Security Intelligence</p>
        </div>
      </div>
    </footer>
  );
}
