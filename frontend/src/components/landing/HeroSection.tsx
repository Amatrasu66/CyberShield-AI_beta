import { useNavigate } from 'react-router-dom';
import { Button } from '../ui';

export function HeroSection() {
  const navigate = useNavigate();

  return (
    <section aria-labelledby="landing-hero-heading" data-testid="hero-section">
      <p className="eyebrow">CyberShield / Security Intelligence</p>
      <h1 id="landing-hero-heading">Know your exposure. Act with confidence.</h1>
      <p>A focused workspace for security assessments, threat visibility, and practical remediation.</p>
      <div>
        <Button type="button" onClick={() => void navigate('/register')}>
          Get Started
        </Button>
        <a href="#capabilities">Explore Security Tools</a>
      </div>
    </section>
  );
}
