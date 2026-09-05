import { useRef, type MouseEvent as ReactMouseEvent, type ReactNode } from 'react';
import { cn } from '../../utils/cn';

export interface HighlightProps {
  readonly children: ReactNode;
  readonly className?: string;
}

/**
 * Grouping wrapper for HighlightItem rows.
 * Local stand-in for the `@/components/unlumen-ui/primitives/effects/highlight`
 * primitive, which does not exist in this repository. No external UI library added.
 */
export function Highlight({ children, className }: HighlightProps) {
  return <div className={cn(className)}>{children}</div>;
}

export interface HighlightItemProps {
  readonly children: ReactNode;
  readonly className?: string;
}

/**
 * Single navigation row with a subtle pointer-tracking spotlight.
 * Position is tracked per item via CSS variables (no re-renders) and rendered
 * with existing theme tokens only — no new design system.
 */
export function HighlightItem({ children, className }: HighlightItemProps) {
  const ref = useRef<HTMLDivElement>(null);

  function handlePointerMove(event: ReactMouseEvent<HTMLDivElement>) {
    const el = ref.current;
    if (el === null) return;
    const rect = el.getBoundingClientRect();
    el.style.setProperty('--highlight-x', `${event.clientX - rect.left}px`);
    el.style.setProperty('--highlight-y', `${event.clientY - rect.top}px`);
  }

  return (
    <div ref={ref} onMouseMove={handlePointerMove} className={cn('group relative', className)}>
      <span
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 rounded-[inherit] opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{
          background:
            'radial-gradient(220px circle at var(--highlight-x, 50%) var(--highlight-y, 50%), rgb(var(--color-primary) / 0.12), transparent 70%)',
        }}
      />
      {children}
    </div>
  );
}
