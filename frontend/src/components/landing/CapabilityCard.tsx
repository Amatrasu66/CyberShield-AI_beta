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
  readonly index: number;
  readonly total: number;
}

/**
 * Content-driven CyberShield capability card. Purely presentational —
 * scroll animation is applied by the parent stack wrapper.
 *
 * Internal layout is a single flex column with three deliberate zones
 * (top meta row / main copy / bottom action row) sharing one left edge.
 * No absolute positioning for content, no images, no decorative UI.
 */
export function CapabilityCard({ capability, index, total }: CapabilityCardProps) {
  const Icon = capability.icon;
  const titleId = `capability-${capability.number}-title`;
  const counter = `${capability.number} / ${String(total).padStart(2, '0')}`;

  return (
    <article
      aria-labelledby={titleId}
      className="relative flex min-h-[320px] w-full flex-col overflow-hidden rounded-xl border border-border bg-card p-6 text-card-foreground sm:min-h-[360px] sm:p-8 lg:p-10"
    >
      <span
        aria-hidden="true"
        className="absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent"
      />

      {/* Top area: module eyebrow left, icon right — one intentional row. */}
      <div className="flex items-center justify-between gap-4">
        <p className="font-mono text-[11px] font-medium uppercase tracking-[0.16em] text-on-surface-variant">
          Module {capability.number}
        </p>
        <span className="grid h-11 w-11 shrink-0 place-items-center rounded-lg border border-border bg-muted text-primary">
          <Icon size={20} aria-hidden="true" />
        </span>
      </div>

      {/* Main area: title + description share the card's left edge. */}
      <div className="mt-7 sm:mt-8">
        <h3
          id={titleId}
          className="font-display text-2xl font-bold uppercase tracking-tight text-on-surface sm:text-[28px] sm:leading-9"
        >
          {capability.title}
        </h3>
        <p className="mt-3 max-w-xl text-sm leading-6 text-on-surface-variant">
          {capability.description}
        </p>
      </div>

      {/* Bottom area: action left, position counter right. */}
      <div className="mt-auto flex items-end justify-between gap-4 pt-8">
        <Link
          to={capability.to}
          aria-label={`${capability.action} — ${capability.title}`}
          className="inline-flex items-center gap-2 self-start rounded-sm text-sm font-semibold text-primary transition hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {capability.action}
          <ArrowRight size={15} aria-hidden="true" />
        </Link>
        <p
          aria-hidden="true"
          className="shrink-0 font-mono text-[11px] font-medium uppercase tracking-[0.16em] text-on-surface-variant"
        >
          {counter}
        </p>
      </div>

      {/* Screen-reader-only position cue (counter above is aria-hidden). */}
      <span className="sr-only">
        Module {index + 1} of {total}
      </span>
    </article>
  );
}
