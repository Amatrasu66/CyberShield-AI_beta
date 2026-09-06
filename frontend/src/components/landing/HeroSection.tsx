import { Suspense, lazy } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../ui';

const HeroVisual = lazy(() => import('./HeroVisual').then((module) => ({ default: module.HeroVisual })));

function HeroVisualFallback() {
  return (
    <div
      aria-hidden="true"
      className="h-[340px] w-full animate-pulse rounded-xl bg-surface-high/40 sm:h-[440px] lg:h-[600px]"
    />
  );
}

export function HeroSection() {
  const navigate = useNavigate();

  return (
    <section
      aria-labelledby="landing-hero-heading"
      data-testid="hero-section"
      className="relative overflow-hidden"
    >
      {/* Phase 7.4 — top-whitespace correction. Cause: the fixed-navbar
          spacer (h-16 = 64px, correct — keep) stacked with the hero inner
          top padding (pt-10 / sm:pt-12 / lg:pt-14 = 40/48/56px), producing
          104–120px of empty space before the eyebrow. On desktop the
          items-center centering of the copy column against the 600px visual
          pushed the headline down further. Fix: reduce the inner top
          padding only (spacer untouched, no negative margins), keep
          items-center so the two columns stay vertically balanced, and
          keep bottom padding slightly larger than top for balance. */}
      <div className="mx-auto grid max-w-6xl items-center gap-8 px-4 pb-12 pt-6 sm:px-6 sm:pt-8 lg:grid-cols-[1.05fr_0.95fr] lg:gap-12 lg:px-8 lg:pb-16 lg:pt-10">
        <div className="min-w-0 max-w-2xl">
          <p className="eyebrow mb-4">CyberShield / Security Intelligence</p>
          <h1
            id="landing-hero-heading"
            className="max-w-[22ch] break-words font-display text-[clamp(1.875rem,1.4rem+2.8vw,3.25rem)] font-bold leading-[1.08] tracking-tight text-on-surface text-balance"
          >
            Know your exposure. Act with confidence.
          </h1>
          <p className="mt-5 max-w-xl text-base leading-7 text-on-surface-variant">
            A focused workspace for security assessments, threat visibility, and practical remediation.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Button type="button" onClick={() => void navigate('/register')}>
              Get Started
            </Button>
            <a
              href="#capabilities"
              className="inline-flex h-10 items-center justify-center gap-2 rounded border border-border px-4 text-sm font-semibold text-on-surface transition hover:bg-surface-high/60"
            >
              Explore Security Tools
            </a>
          </div>
        </div>

        <div className="relative">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 bg-[radial-gradient(closest-side,rgba(99,102,241,0.22),transparent)] blur-2xl"
          />
          <div aria-hidden="true" className="relative h-[340px] sm:h-[440px] lg:h-[600px]">
            <Suspense fallback={<HeroVisualFallback />}>
              <HeroVisual />
            </Suspense>
          </div>
        </div>
      </div>
    </section>
  );
}
