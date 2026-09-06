import { TopologyField } from './TopologyField';

/**
 * Phase 7.2 — Hero visual renders the React-native ThreeUI topology field
 * directly in the hero DOM. No iframe, no embedded demo page, no
 * card chrome — the transparent canvas dissolves into the hero background.
 */
export function HeroVisual() {
  return (
    <div data-testid="hero-visual" className="h-full w-full bg-transparent">
      <TopologyField />
    </div>
  );
}
