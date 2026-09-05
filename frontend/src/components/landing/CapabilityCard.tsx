import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export interface Capability {
  readonly number: string;
  readonly title: string;
  readonly description: string;
  readonly to: string;
  readonly action: string;
  readonly icon: LucideIcon;
}

interface CapabilityCardProps {
  readonly capability: Capability;
}

/**
 * Content-driven CyberShield capability card. Purely presentational —
 * scroll animation is applied by the parent stack wrapper.
 */
export function CapabilityCard({ capability }: CapabilityCardProps) {
  const Icon = capability.icon;
  return (
    <article className="relative flex min-h-[300px] flex-col overflow-hidden rounded-lg border border-border bg-card p-7 text-card-foreground sm:min-h-[330px] sm:p-9 lg:min-h-[360px]">
      <span
        aria-hidden="true"
        className="absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent"
      />
      <div className="flex items-start gap-5">
        <span className="grid h-12 w-12 shrink-0 place-items-center rounded-lg border border-border bg-surface-high/60 text-primary">
          <Icon size={22} />
        </span>
        <div className="min-w-0">
          <p className="font-mono text-[11px] font-medium uppercase tracking-[0.16em] text-on-surface-variant">
            Module {capability.number}
          </p>
          <h3 className="mt-2 font-display text-2xl font-bold uppercase tracking-tight text-on-surface sm:text-[28px] sm:leading-9">
            {capability.title}
          </h3>
        </div>
      </div>
      <p className="mt-4 max-w-md text-sm leading-6 text-on-surface-variant">{capability.description}</p>
      <Link
        to={capability.to}
        className="mt-auto inline-flex items-center gap-2 self-start pt-7 text-sm font-semibold text-primary transition hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {capability.action}
        <ArrowRight size={15} aria-hidden="true" />
      </Link>
    </article>
  );
}
