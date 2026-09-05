import { CapabilityStack } from './CapabilityStack';

export function SecurityCapabilities() {
  return (
    <section
      aria-labelledby="landing-capabilities-heading"
      id="capabilities"
      data-testid="security-capabilities"
      className="relative"
    >
      <div className="mx-auto grid max-w-6xl gap-10 px-4 py-16 sm:px-6 lg:grid-cols-[0.9fr_1.1fr] lg:gap-14 lg:px-8 lg:py-24">
        <div className="lg:sticky lg:top-28 lg:self-start">
          <p className="eyebrow mb-4">Capabilities</p>
          <h2
            id="landing-capabilities-heading"
            className="font-display text-3xl font-bold tracking-tight text-on-surface sm:text-4xl lg:text-[40px] lg:leading-[48px]"
          >
            Security tools,
            <br />
            without the noise.
          </h2>
          <p className="mt-5 max-w-md text-sm leading-6 text-on-surface-variant">
            Eight focused modules from the CyberShield workspace. Each one runs against systems you own or
            have permission to test.
          </p>
        </div>
        <CapabilityStack />
      </div>
    </section>
  );
}
