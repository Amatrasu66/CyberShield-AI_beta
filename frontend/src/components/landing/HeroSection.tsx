import { Suspense, lazy } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '../ui';

const HeroVisual = lazy(() => import('./HeroVisual').then((module) => ({ default: module.HeroVisual })));

function HeroVisualFallback() {
  return (
    <div
      aria-hidden="true"
      className="h-[300px] w-full animate-pulse rounded-xl bg-surface-high/40 sm:h-[380px] lg:h-[520px]"
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
      <div className="mx-auto grid max-w-6xl items-center gap-10 px-4 py-16 sm:px-6 lg:grid-cols-[1.05fr_0.95fr] lg:gap-12 lg:px-8 lg:py-24">
        <div>
          <p className="eyebrow mb-4">CyberShield / Security Intelligence</p>
          <h1
            id="landing-hero-heading"
            className="font-display text-4xl font-bold leading-[1.08] tracking-tight text-on-surface sm:text-5xl lg:text-6xl"
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
          <div aria-hidden="true" className="relative h-[300px] sm:h-[380px] lg:h-[520px]">
            <Suspense fallback={<HeroVisualFallback />}>
              <HeroVisual />
            </Suspense>
          </div>
        </div>
      </div>
    </section>
  );
}
