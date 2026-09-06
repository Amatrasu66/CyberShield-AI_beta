import { StructureFlowCollection } from '../../shaders/StructureFlowCollection';
import '../../shaders/threeui.css';

/**
 * Phase 7.1 — Hero topology replaced with the exact authored ThreeUI
 * Topology Field (source revision SHA-256 40eb5bac81e3).
 *
 * Configured usage (local path equivalent of `@designcodeio/threeui`):
 *   <div className="shader-frame">
 *     <StructureFlowCollection variant="topology-field" hue={0} saturation={1} brightness={1} />
 *   </div>
 *
 * The previous custom @react-three/fiber implementation has been removed.
 * No host Three.js version change was needed: the authored field runs
 * Three.js r128 inside its isolated iframe (nexus-topology.html), independent
 * of the host `three` dependency.
 *
 * Theme: the authored field is fixed dark (#070707, no light variant), so the
 * wrapper keeps a local dark ground in both app themes. No global theme
 * system changes. The iframe isolates pointer events to its background role
 * (pointer-events:none inside), and this column never overlaps hero copy/CTA.
 */
export function HeroVisual() {
  return (
    <div data-testid="hero-visual" className="h-full w-full">
      <div className="shader-frame h-full w-full overflow-hidden rounded-xl bg-[#070707]">
        <StructureFlowCollection variant="topology-field" hue={0} saturation={1.0} brightness={1.0} />
      </div>
    </div>
  );
}
