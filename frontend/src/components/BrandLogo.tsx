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
 * - Light theme  -> accented asset (light logo / accented mark)
 * - Dark theme   -> monochrome/dark asset
 * Follows existing useTheme.effective (including system resolution).
 * Referenced as static public assets — never via dangerouslySetInnerHTML.
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
  const src = isMark
    ? effective === 'dark'
      ? '/cybershield-mark-dark.svg'
      : '/cybershield-mark-light.svg'
    : effective === 'dark'
      ? '/cybershield-logo-dark.svg'
      : '/cybershield-logo-light.svg';

  const resolvedAlt = decorative ? '' : (alt ?? 'CyberShield');

  // Sensible intrinsic dimensions to avoid CLS; CSS controls rendered size.
  const intrinsic = isMark
    ? { w: 48, h: 48 }
    : { w: 168, h: 32 };

  return (
    <img
      src={src}
      alt={resolvedAlt}
      aria-hidden={decorative || undefined}
      width={width ?? intrinsic.w}
      height={height ?? intrinsic.h}
      decoding="async"
      // Keep aspect, prevent overflow / distortion per spec section 9
      className={cn('max-w-full object-contain', isMark ? 'shrink-0' : 'h-8 w-auto', className)}
    />
  );
}

export function BrandMark(props: Omit<BrandLogoProps, 'variant'>) {
  return <BrandLogo {...props} variant="mark" />;
}
