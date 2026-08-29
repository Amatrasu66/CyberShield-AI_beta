import { useTheme } from '../hooks/useTheme';
import { cn } from '../utils/cn';

export type BrandLogoVariant = 'full' | 'mark';

export interface BrandLogoProps {
  readonly variant?: BrandLogoVariant;
  readonly className?: string;
  readonly alt?: string;
  readonly decorative?: boolean;
  readonly width?: number;
  readonly height?: number;
}

/**
 * Theme-aware CyberShield brand mark/logo.
 * - Full logo (variant="full") -> now renders BrandLockup (mark + coded text) per Phase 3A-8C
 * - Mark (variant="mark")      -> theme-aware: light -> /cybershield-mark-light.svg, dark -> /cybershield-mark-dark.svg
 * Follows existing useTheme.effective (including system resolution).
 * Referenced as static public assets — never via dangerouslySetInnerHTML.
 * Full wordmark SVG (/cybershield-logo-light.svg) remains in public/ but is no longer used for lockup.
 */
export function BrandLogo({
  variant = 'full',
  className,
  alt,
  decorative = false,
  width,
  height,
}: BrandLogoProps) {
  const { effective } = useTheme();

  const isMark = variant === 'mark';
  // Full variant now delegates to lockup for readability on dark UI
  if (!isMark) {
    return <BrandLockup size="sidebar" className={className} />;
  }

  const src = effective === 'dark' ? '/cybershield-mark-dark.svg' : '/cybershield-mark-light.svg';
  const resolvedAlt = decorative ? '' : (alt ?? 'CyberShield');

  return (
    <img
      src={src}
      alt={resolvedAlt}
      aria-hidden={decorative || undefined}
      width={width ?? 48}
      height={height ?? 48}
      decoding="async"
      className={cn('max-w-full shrink-0 object-contain', className)}
    />
  );
}

export function BrandMark(props: Omit<BrandLogoProps, 'variant'>) {
  return <BrandLogo {...props} variant="mark" />;
}

// ---------------------------------------------------------------------------
// BrandLockup — reusable mark + application-rendered text
// ---------------------------------------------------------------------------

export type BrandLockupSize = 'sidebar' | 'login';

export interface BrandLockupProps {
  readonly size?: BrandLockupSize;
  readonly className?: string;
  /** Optional extra classes for the mark image */
  readonly markClassName?: string;
}

export function BrandLockup({ size = 'sidebar', className, markClassName }: BrandLockupProps) {
  const { effective } = useTheme();
  const src = effective === 'dark' ? '/cybershield-mark-dark.svg' : '/cybershield-mark-light.svg';

  const isLogin = size === 'login';

  // Sidebar: mark 32px (h-8), fits 280px sidebar. Login: mark 48-52px (h-12)
  const markSize = isLogin ? 'h-12 w-12' : 'h-8 w-8';
  // Typography: use existing design language with theme-aware semantic tokens
  // CYBERSHIELD: readable primary (on-surface), SECURITY INTELLIGENCE: secondary (on-surface-variant)
  // Do not introduce new font; use font-display / font-body already in project
  return (
    <div
      className={cn(
        'flex items-center gap-3 overflow-hidden',
        isLogin ? 'max-w-[320px]' : 'max-w-[240px]',
        className,
      )}
      aria-label="CyberShield — Security Intelligence"
    >
      <img
        src={src}
        alt=""
        aria-hidden="true"
        width={isLogin ? 48 : 32}
        height={isLogin ? 48 : 32}
        decoding="async"
        className={cn('shrink-0 object-contain', markSize, markClassName)}
      />
      <div className="flex min-w-0 flex-col leading-none">
        <span
          className={cn(
            'truncate font-display font-bold tracking-tight text-on-surface',
            isLogin ? 'text-[17px] sm:text-lg' : 'text-[13px] sm:text-sm',
          )}
        >
          CYBERSHIELD
        </span>
        <span
          className={cn(
            'truncate font-mono uppercase tracking-[0.14em] text-on-surface-variant',
            isLogin ? 'mt-0.5 text-[10px] sm:text-[11px]' : 'mt-0.5 text-[9px] sm:text-[10px]',
          )}
        >
          SECURITY INTELLIGENCE
        </span>
      </div>
    </div>
  );
}
