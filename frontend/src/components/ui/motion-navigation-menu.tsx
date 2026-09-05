import { AnimatePresence, motion } from 'framer-motion';
import { ChevronDown } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import type { LucideIcon } from 'lucide-react';
import { cn } from '../../utils/cn';
import { Highlight, HighlightItem } from './highlight';

export interface MotionNavigationLink {
  readonly label: string;
  /** Route path (e.g. `/website-scanner`) or in-page anchor (e.g. `#workflow`). */
  readonly to: string;
  readonly description?: string;
  readonly icon?: LucideIcon;
}

export interface MotionNavigationEntry {
  readonly label: string;
  /** Plain link destination when `links` is absent. */
  readonly to?: string;
  /** Dropdown content when present. */
  readonly links?: readonly MotionNavigationLink[];
}

export interface MotionNavigationMenuProps {
  readonly entries: readonly MotionNavigationEntry[];
  readonly className?: string;
}

const VIEWPORT_SPRING = { type: 'spring', stiffness: 380, damping: 34 } as const;
const CONTENT_SPRING = { type: 'spring', stiffness: 420, damping: 34 } as const;
const CHEVRON_SPRING = { type: 'spring', stiffness: 400, damping: 26 } as const;

/** Replaces the supplied source's small `cva()` trigger style — no extra dependency. */
function triggerClassName(active: boolean) {
  return cn(
    'inline-flex items-center gap-1.5 rounded-full px-4 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
    active
      ? 'bg-surface-high/70 text-on-surface'
      : 'text-on-surface-variant hover:bg-surface-high/50 hover:text-on-surface',
  );
}

function isAnchor(to: string) {
  return to.startsWith('#');
}

interface DropdownLinkProps {
  readonly link: MotionNavigationLink;
  readonly onNavigate: () => void;
}

function DropdownLink({ link, onNavigate }: DropdownLinkProps) {
  const Icon = link.icon;
  const content = (
    <>
      {Icon !== undefined && (
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-md bg-primary/10 text-primary">
          <Icon size={17} />
        </span>
      )}
      <span className="min-w-0">
        <span className="block truncate text-sm font-medium text-on-surface">{link.label}</span>
        {link.description !== undefined && (
          <span className="block truncate text-xs text-on-surface-variant">{link.description}</span>
        )}
      </span>
    </>
  );
  const className =
    'relative flex items-center gap-3 rounded-lg px-3 py-2.5 transition-colors hover:bg-surface-high/60';
  return (
    <HighlightItem className="rounded-lg">
      {isAnchor(link.to) ? (
        <a href={link.to} onClick={onNavigate} className={className}>
          {content}
        </a>
      ) : (
        <Link to={link.to} onClick={onNavigate} className={className}>
          {content}
        </Link>
      )}
    </HighlightItem>
  );
}

/**
 * Animated navigation menu: hover/focus-activated dropdown viewport with spring
 * transitions, directional content transitions, animated chevron, Escape and
 * outside-click dismissal, and viewport-clamped responsive positioning.
 */
export function MotionNavigationMenu({ entries, className }: MotionNavigationMenuProps) {
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const [direction, setDirection] = useState<1 | -1>(1);
  const rootRef = useRef<HTMLDivElement>(null);
  const closeTimer = useRef<number | null>(null);

  const activeEntry = openIndex === null ? null : (entries[openIndex] ?? null);
  const activeLinks = activeEntry?.links ?? null;
  const wide = (activeLinks?.length ?? 0) > 2;

  function cancelClose() {
    if (closeTimer.current !== null) {
      window.clearTimeout(closeTimer.current);
      closeTimer.current = null;
    }
  }

  function scheduleClose() {
    cancelClose();
    closeTimer.current = window.setTimeout(() => setOpenIndex(null), 140);
  }

  function openEntry(index: number) {
    cancelClose();
    setDirection(index > (openIndex ?? -1) ? 1 : -1);
    setOpenIndex(index);
  }

  function close() {
    cancelClose();
    setOpenIndex(null);
  }

  useEffect(() => {
    return () => {
      if (closeTimer.current !== null) window.clearTimeout(closeTimer.current);
    };
  }, []);

  useEffect(() => {
    if (openIndex === null) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpenIndex(null);
    }
    function onPointerDown(event: MouseEvent) {
      const root = rootRef.current;
      if (root !== null && !root.contains(event.target as Node)) setOpenIndex(null);
    }
    document.addEventListener('keydown', onKeyDown);
    document.addEventListener('mousedown', onPointerDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.removeEventListener('mousedown', onPointerDown);
    };
  }, [openIndex]);

  return (
    <div ref={rootRef} className={cn('relative', className)} onMouseEnter={cancelClose} onMouseLeave={scheduleClose}>
      <ul className="flex items-center gap-1">
        {entries.map((entry, index) => {
          const open = openIndex === index;
          if (entry.links === undefined) {
            return (
              <li key={entry.label}>
                <a
                  href={entry.to ?? '#'}
                  onMouseEnter={() => setOpenIndex(null)}
                  onFocus={() => setOpenIndex(null)}
                  className={triggerClassName(false)}
                >
                  {entry.label}
                </a>
              </li>
            );
          }
          return (
            <li key={entry.label}>
              <button
                type="button"
                aria-expanded={open}
                aria-haspopup="true"
                onMouseEnter={() => openEntry(index)}
                onFocus={() => openEntry(index)}
                onClick={() => (open ? close() : openEntry(index))}
                className={triggerClassName(open)}
              >
                {entry.label}
                <motion.span
                  aria-hidden="true"
                  animate={{ rotate: open ? 180 : 0 }}
                  transition={CHEVRON_SPRING}
                  className="grid place-items-center"
                >
                  <ChevronDown size={15} />
                </motion.span>
              </button>
            </li>
          );
        })}
      </ul>

      <AnimatePresence>
        {activeLinks !== null && (
          <motion.div
            key="motion-nav-viewport"
            initial={{ opacity: 0, y: 8, x: '-50%' }}
            animate={{ opacity: 1, y: 0, x: '-50%' }}
            exit={{ opacity: 0, y: 6, x: '-50%' }}
            transition={VIEWPORT_SPRING}
            className="absolute left-1/2 top-full z-50 pt-2"
          >
            <div
              className={cn(
                'overflow-hidden rounded-xl border border-border bg-popover text-popover-foreground shadow-xl',
                wide ? 'w-[min(92vw,38rem)]' : 'w-[min(92vw,18rem)]',
              )}
            >
              <AnimatePresence mode="wait" initial={false}>
                <motion.div
                  key={openIndex}
                  initial={{ opacity: 0, x: 28 * direction }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 * direction }}
                  transition={CONTENT_SPRING}
                >
                  <Highlight className={cn('grid gap-1 p-2', wide && 'sm:grid-cols-2')}>
                    {activeLinks.map((link) => (
                      <DropdownLink key={link.label} link={link} onNavigate={close} />
                    ))}
                  </Highlight>
                </motion.div>
              </AnimatePresence>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
