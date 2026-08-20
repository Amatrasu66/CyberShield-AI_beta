import { Loader2 } from 'lucide-react';
import { cn } from '../utils/cn';

export interface SlowRequestNoticeProps {
  readonly elapsedSeconds: number;
  readonly className?: string;
}

function formatElapsed(totalSeconds: number): string {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

/**
 * Indeterminate waiting state shown once an authenticated request has been
 * in-flight for several seconds. It explains that the security backend may be
 * waking up after inactivity, never invents a percentage or startup progress,
 * and keeps the notice purely informational while the request continues.
 */
export function SlowRequestNotice({ elapsedSeconds, className }: SlowRequestNoticeProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn('rounded-lg border border-primary/20 bg-primary/5 p-4', className)}
    >
      <div className="flex items-start gap-3">
        <span className="mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded bg-primary/10 text-primary">
          <Loader2 size={18} className="animate-spin" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-display text-sm font-semibold text-on-surface">
            The security backend may be waking up…
          </p>
          <p className="mt-1 text-sm leading-6 text-on-surface-variant">
            After a period of inactivity the backend can take a minute or two to
            respond again. This request is still running — we&apos;ll show the
            result as soon as it arrives, no need to retry.
          </p>
        </div>
      </div>
      <div className="mt-4 flex items-center gap-3">
        <div className="indeterminate-track w-32" aria-hidden="true" />
        <span className="font-mono text-xs text-primary tabular-nums">
          Elapsed: {formatElapsed(elapsedSeconds)}
        </span>
      </div>
    </div>
  );
}