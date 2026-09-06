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
      {/* Phase 7.5 — desktop hero vertical-spacing fix. Cause: items-center
          centered the left copy column against the 600px right visual,
          pushing the eyebrow/headline downward; lg:pt-10 (40px) added
          further top whitespace. Fix: keep base items-center for
          mobile/tablet, switch desktop to lg:items-start so the copy
          begins near the top of the grid while the topology stays in its
          existing right-side position; reduce desktop top padding to
          lg:pt-6 (24px) for a small controlled navbar→eyebrow gap. No
          negative margins, absolute positioning, transforms, JS, or
          topology changes. */}
      <div className="mx-auto grid max-w-6xl items-center gap-8 px-4 pb-12 pt-6 sm:px-6 sm:pt-8 lg:grid-cols-[1.05fr_0.95fr] lg:items-start lg:gap-12 lg:px-8 lg:pb-16 lg:pt-6">
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
