import type { CSSProperties } from 'react';
import { TopologyField } from './neuform-isolated/NeuformIsolatedEffects';

/**
 * Local adapter matching the configured ThreeUI usage:
 *
 *   import { StructureFlowCollection } from "@designcodeio/threeui";
 *   <StructureFlowCollection variant="topology-field" hue={0} saturation={1} brightness={1} />
 *
 * The topology-field bundle (SHA-256 40eb5bac81e3) ships `TopologyField`
 * (EFFECTS.topology, #animationCanvas isolated from nexus-topology.html).
 * `StructureFlowCollection` is not present in the bundle, so this thin
 * adapter maps `variant="topology-field"` to the exact authored component
 * without rewriting its shader, isolation logic, or props.
 *
 * Only `topology-field` is bundled in Phase 7.1. Other variants render null.
 */
export type StructureFlowCollectionVariant = 'topology-field';

export interface StructureFlowCollectionProps {
  readonly variant: StructureFlowCollectionVariant;
  readonly hue?: number;
  readonly saturation?: number;
  readonly brightness?: number;
  readonly className?: string;
  readonly style?: CSSProperties;
}

export function StructureFlowCollection({
  variant,
  hue = 0,
  saturation = 1,
  brightness = 1,
  className,
  style,
}: StructureFlowCollectionProps) {
  if (variant !== 'topology-field') return null;
  return (
    <TopologyField
      hue={hue}
      saturation={saturation}
      brightness={brightness}
      className={className}
      style={style}
    />
  );
}
