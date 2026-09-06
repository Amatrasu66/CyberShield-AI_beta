import { Suspense, lazy } from 'react';

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
  return (
    <section
      aria-labelledby="landing-hero-heading"
      data-testid="hero-section"
      className="relative overflow-hidden"
    >
      {/* Phase 7.9 — match reference: remove 7.8's lg:-translate-y-4
          (grid stays items-center), compact desktop vertical footprint via
          lg:pb-16 → lg:pb-8 so text + topology sit higher with moderate
          controlled navbar gap. lg:pt-0 kept at zero; mobile, typography,
          copy, topology, and navbar untouched. */}
      <div className="mx-auto grid max-w-6xl items-center gap-8 px-4 pb-12 pt-6 sm:px-6 sm:pt-8 lg:grid-cols-[1.05fr_0.95fr] lg:gap-12 lg:px-8 lg:pb-8 lg:pt-0">
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
