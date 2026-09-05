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
      <HeroSection />
      <SecurityCapabilities />
      <WorkflowSection />
      <FinalCTA />
      <LandingFooter />
    </main>
  );
}
