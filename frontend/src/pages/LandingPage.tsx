import { LandingNavbar } from '../components/landing/LandingNavbar';
import { HeroSection } from '../components/landing/HeroSection';
import { SecurityCapabilities } from '../components/landing/SecurityCapabilities';
import { WorkflowSection } from '../components/landing/WorkflowSection';
import { FinalCTA } from '../components/landing/FinalCTA';
import { LandingFooter } from '../components/landing/LandingFooter';

export function LandingPage() {
  return (
    <main data-testid="landing-page">
      <LandingNavbar />
      {/* Fixed h-16 offset for the fixed auto-hiding navbar. Constant height
          (never animates), so no content jump on hide/show. Transparent —
          renders page background only, so it produces no visible divider. */}
      <div aria-hidden="true" className="h-16" />
      <HeroSection />
      <SecurityCapabilities />
      <WorkflowSection />
      <FinalCTA />
      <LandingFooter />
    </main>
  );
}
