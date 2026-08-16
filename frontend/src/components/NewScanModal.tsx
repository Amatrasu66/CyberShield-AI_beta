import { useEffect, useRef } from 'react';
import type { LucideIcon } from 'lucide-react';
import { BarChart3, Globe, KeyRound, MailWarning, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { Button, Card } from './ui';
import { cn } from '../utils/cn';

interface ScanTypeOption {
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly icon: LucideIcon;
  readonly route: string;
}

const SCAN_TYPES: readonly ScanTypeOption[] = [
  { id: 'website', label: 'Website Scanner', description: 'Inspect a public URL for headers, TLS posture, and configuration weaknesses.', icon: Globe, route: '/website-scanner' },
  { id: 'email', label: 'Email Detector', description: 'Analyze suspicious message content for phishing language and risky indicators.', icon: MailWarning, route: '/email-detector' },
  { id: 'password', label: 'Password Analyzer', description: 'Measure password strength using length, entropy, and exposure signals.', icon: KeyRound, route: '/password-analyzer' },
  { id: 'log', label: 'Log Analyzer', description: 'Upload or paste server events to identify anomalous activity and priority incidents.', icon: BarChart3, route: '/log-analyzer' },
];

export interface NewScanModalProps { readonly onClose: () => void; }

export function NewScanModal({ onClose }: NewScanModalProps) {
  const navigate = useNavigate();
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;
      const focusable = panelRef.current?.querySelectorAll<HTMLElement>('button');
      if (!focusable || focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      previouslyFocused?.focus?.();
    };
  }, [onClose]);

  const handleSelect = (route: string) => {
    onClose();
    navigate(route);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="new-scan-title"
        aria-describedby="new-scan-description"
        tabIndex={-1}
        className="relative w-full max-w-lg focus:outline-none"
      >
        <Card className="p-6">
          <div className="mb-5 flex items-start justify-between gap-4">
            <div>
              <p className="eyebrow mb-2">New assessment</p>
              <h2 id="new-scan-title" className="font-display text-xl font-bold tracking-tight">Choose a scan type</h2>
              <p id="new-scan-description" className="mt-1 text-sm text-on-surface-variant">
                Select the assessment you want to run against your target.
              </p>
            </div>
            <Button variant="ghost" className="h-9 w-9 p-0" aria-label="Close new scan dialog" title="Close" onClick={onClose}>
              <X size={18} />
            </Button>
          </div>
          <div className="grid gap-3">
            {SCAN_TYPES.map((option, index) => {
              const Icon = option.icon;
              return (
                <button
                  key={option.id}
                  type="button"
                  onClick={() => handleSelect(option.route)}
                  autoFocus={index === 0}
                  aria-label={`Run ${option.label} scan`}
                  className={cn(
                    'flex items-center gap-4 rounded border bg-surface-low p-4 text-left transition',
                    'hover:border-primary hover:bg-primary/5 focus:outline-none focus:ring-2 focus:ring-primary/60'
                  )}
                >
                  <span className="grid h-10 w-10 shrink-0 place-items-center rounded bg-primary/10 text-primary">
                    <Icon size={20} />
                  </span>
                  <span>
                    <span className="block font-semibold">{option.label}</span>
                    <span className="mt-0.5 block text-sm leading-5 text-on-surface-variant">{option.description}</span>
                  </span>
                </button>
              );
            })}
          </div>
          <div className="mt-6 flex justify-end">
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
}