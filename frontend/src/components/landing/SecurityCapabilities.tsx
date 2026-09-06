import { CapabilityStack } from './CapabilityStack';

export function SecurityCapabilities() {
  return (
    <section
      aria-labelledby="landing-capabilities-heading"
      id="capabilities"
      data-testid="security-capabilities"
      className="relative overflow-x-clip"
    >
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="pt-16 lg:pt-24">
          <p className="eyebrow mb-4">Capabilities</p>
          <h2
            id="landing-capabilities-heading"
            className="font-display text-3xl font-bold tracking-tight text-on-surface sm:text-4xl lg:text-[40px] lg:leading-[48px]"
          >
            Security tools,
            <br />
            without the noise.
          </h2>
          <div className="mt-5 flex flex-wrap items-end justify-between gap-x-8 gap-y-4">
            <p className="max-w-md text-sm leading-6 text-on-surface-variant">
              Eight focused modules from the CyberShield workspace. Each one runs against systems you
              own or have permission to test.
            </p>
            <p
              aria-hidden="true"
              className="shrink-0 font-mono text-[11px] font-medium uppercase tracking-[0.16em] text-on-surface-variant"
            >
              Scroll to explore — 08 modules
            </p>
          </div>
        </div>
        <CapabilityStack />
      </div>
    </section>
  );
}
