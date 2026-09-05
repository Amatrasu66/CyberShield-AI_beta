import { Link } from 'react-router-dom';
import { BrandLockup } from '../BrandLogo';

export function LandingNavbar() {
  return (
    <header data-testid="landing-navbar">
      <nav aria-label="Primary">
        <Link to="/" aria-label="CyberShield — Home">
          <BrandLockup size="sidebar" />
        </Link>
        <ul>
          <li>
            <a href="#capabilities">Capabilities</a>
          </li>
          <li>
            <a href="#workflow">How it works</a>
          </li>
          <li>
            <a href="#cta">Get started</a>
          </li>
        </ul>
        <div>
          <Link to="/login">Sign in</Link>
          <Link to="/register">Create account</Link>
        </div>
      </nav>
    </header>
  );
}
