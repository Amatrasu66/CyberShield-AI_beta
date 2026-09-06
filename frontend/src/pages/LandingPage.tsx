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
      {/* Phase 7.3 — constant h-16 offset for the fixed auto-hiding navbar.
          Fixed height (never animates), so no content jump on hide/show. */}
      <div aria-hidden="true" className="h-16" />
      <HeroSection />
      <SecurityCapabilities />
      <WorkflowSection />
      <FinalCTA />
      <LandingFooter />
    </main>
  );
}
