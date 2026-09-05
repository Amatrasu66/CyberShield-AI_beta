import { useEffect, useMemo, useRef, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';

const NODE_TARGET = 70;
const FOCAL_COUNT = 10;
const CHORD_COUNT = 12;
const SPHERE_RADIUS = 2.15;
const ROTATION_SPEED = 0.06;
const POINTER_TILT = 0.16;

interface TopologyPalette {
  readonly line: string;
  readonly lineOpacity: number;
  readonly chordOpacity: number;
  readonly node: string;
  readonly focal: string;
}

const DARK_PALETTE: TopologyPalette = {
  line: '#22d3ee',
  lineOpacity: 0.32,
  chordOpacity: 0.45,
  node: '#a5b4fc',
  focal: '#ffffff',
};

const LIGHT_PALETTE: TopologyPalette = {
  line: '#0284c7',
  lineOpacity: 0.38,
  chordOpacity: 0.5,
  node: '#4f46e5',
  focal: '#1e1b4b',
};

/** Deterministic PRNG so the topology is stable across renders. */
function mulberry32(seed: number) {
  let state = seed >>> 0;
  return () => {
    state |= 0;
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface TopologyData {
  readonly nodePositions: Float32Array;
  readonly focalPositions: Float32Array;
  readonly linePositions: Float32Array;
  readonly chordPositions: Float32Array;
  readonly nodeCount: number;
  readonly connectionCount: number;
}

function buildTopology(): TopologyData {
  const rand = mulberry32(20260905);
  const points: THREE.Vector3[] = [];
  const seen = new Set<string>();

  const pushUnique = (v: THREE.Vector3) => {
    const key = `${v.x.toFixed(3)}|${v.y.toFixed(3)}|${v.z.toFixed(3)}`;
    if (seen.has(key)) return;
    seen.add(key);
    points.push(v);
  };

  // Icosahedron shell (detail 1 -> 42 unique vertices). Dedupe FIRST on raw
  // positions, then apply one jitter per unique vertex so duplicates stay merged.
  const shell = new THREE.IcosahedronGeometry(SPHERE_RADIUS, 1);
  const shellPositions = shell.getAttribute('position') as THREE.BufferAttribute;
  const tmp = new THREE.Vector3();
  const raw: THREE.Vector3[] = [];
  for (let i = 0; i < shellPositions.count; i += 1) {
    tmp.fromBufferAttribute(shellPositions, i);
    const key = `${tmp.x.toFixed(3)}|${tmp.y.toFixed(3)}|${tmp.z.toFixed(3)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    raw.push(tmp.clone());
  }
  shell.dispose();
  for (const v of raw) {
    const jitter = 1 + (rand() - 0.5) * 0.24;
    points.push(v.multiplyScalar(jitter));
  }

  // Evenly distributed extra surface points (Fibonacci sphere) with slight radial variance.
  const extra = NODE_TARGET - points.length;
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < extra; i += 1) {
    const y = 1 - ((i + 0.5) / extra) * 2;
    const radius = Math.sqrt(Math.max(0, 1 - y * y));
    const theta = goldenAngle * i + rand() * 0.35;
    const r = SPHERE_RADIUS * (1 + (rand() - 0.5) * 0.3);
    pushUnique(new THREE.Vector3(Math.cos(theta) * radius * r, y * r, Math.sin(theta) * radius * r));
  }

  const nodeCount = points.length;

  // Local mesh edges: each node links to its 3 nearest neighbours within a cap.
  const maxEdge = SPHERE_RADIUS * 1.28;
  const pairSet = new Set<string>();
  const degrees = new Array<number>(nodeCount).fill(0);
  const segments: number[] = [];
  for (let i = 0; i < nodeCount; i += 1) {
    const nearest = points
      .map((p, j) => ({ j, d: j === i ? Number.POSITIVE_INFINITY : points[i].distanceTo(p) }))
      .filter((c) => c.d <= maxEdge)
      .sort((a, b) => a.d - b.d)
      .slice(0, 3);
    for (const { j } of nearest) {
      const key = i < j ? `${i}-${j}` : `${j}-${i}`;
      if (pairSet.has(key)) continue;
      pairSet.add(key);
      const a = points[i];
      const b = points[j];
      segments.push(a.x, a.y, a.z, b.x, b.y, b.z);
      degrees[i] += 1;
      degrees[j] += 1;
    }
  }

  // Sparse long-range internal chords across the volume.
  const chords: number[] = [];
  const farPairs: Array<{ i: number; j: number }> = [];
  for (let i = 0; i < nodeCount; i += 1) {
    for (let j = i + 1; j < nodeCount; j += 1) {
      if (points[i].distanceTo(points[j]) > SPHERE_RADIUS * 1.6) farPairs.push({ i, j });
    }
  }
  for (let k = farPairs.length - 1; k > 0; k -= 1) {
    const m = Math.floor(rand() * (k + 1));
    [farPairs[k], farPairs[m]] = [farPairs[m], farPairs[k]];
  }
  for (const { i, j } of farPairs.slice(0, CHORD_COUNT)) {
    const a = points[i];
    const b = points[j];
    chords.push(a.x, a.y, a.z, b.x, b.y, b.z);
  }

  // Focal nodes: highest-degree hubs stay sparse and bright.
  const focalIndices = degrees
    .map((degree, index) => ({ degree, index }))
    .sort((a, b) => b.degree - a.degree)
    .slice(0, FOCAL_COUNT)
    .map((entry) => entry.index);

  const nodePositions = new Float32Array(nodeCount * 3);
  points.forEach((p, i) => {
    nodePositions[i * 3] = p.x;
    nodePositions[i * 3 + 1] = p.y;
    nodePositions[i * 3 + 2] = p.z;
  });

  const focalPositions = new Float32Array(focalIndices.length * 3);
  focalIndices.forEach((nodeIndex, k) => {
    focalPositions[k * 3] = nodePositions[nodeIndex * 3];
    focalPositions[k * 3 + 1] = nodePositions[nodeIndex * 3 + 1];
    focalPositions[k * 3 + 2] = nodePositions[nodeIndex * 3 + 2];
  });

  return {
    nodePositions,
    focalPositions,
    linePositions: new Float32Array(segments),
    chordPositions: new Float32Array(chords),
    nodeCount,
    connectionCount: segments.length / 6 + chords.length / 6,
  };
}

/** Soft round sprite shared by every node — one texture, no per-node materials. */
function makeNodeSprite(): THREE.CanvasTexture {
  const size = 64;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d');
  if (ctx !== null) {
    const gradient = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    gradient.addColorStop(0, 'rgba(255, 255, 255, 1)');
    gradient.addColorStop(0.35, 'rgba(255, 255, 255, 0.85)');
    gradient.addColorStop(1, 'rgba(255, 255, 255, 0)');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, size, size);
  }
  return new THREE.CanvasTexture(canvas);
}

/** Subscribes to the existing `dark` class on <html> — no new theme system. */
function useDarkMode(): boolean {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));
  useEffect(() => {
    const root = document.documentElement;
    const observer = new MutationObserver(() => setDark(root.classList.contains('dark')));
    observer.observe(root, { attributes: true, attributeFilter: ['class'] });
    return () => observer.disconnect();
  }, []);
  return dark;
}

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  );
  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = () => setReduced(query.matches);
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);
  return reduced;
}

interface TopologyProps {
  readonly data: TopologyData;
  readonly palette: TopologyPalette;
  readonly reducedMotion: boolean;
  readonly sprite: THREE.Texture;
}

function Topology({ data, palette, reducedMotion, sprite }: TopologyProps) {
  const group = useRef<THREE.Group>(null);
  const lineMaterial = useRef<THREE.LineBasicMaterial>(null);
  const chordMaterial = useRef<THREE.LineBasicMaterial>(null);
  const nodeMaterial = useRef<THREE.PointsMaterial>(null);
  const focalMaterial = useRef<THREE.PointsMaterial>(null);
  const pointer = useRef({ x: 0, y: 0 });
  const tilt = useRef({ x: 0, y: 0 });

  const geometries = useMemo(() => {
    const make = (positions: Float32Array) => {
      const geometry = new THREE.BufferGeometry();
      geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
      return geometry;
    };
    return {
      nodes: make(data.nodePositions),
      focal: make(data.focalPositions),
      lines: make(data.linePositions),
      chords: make(data.chordPositions),
    };
  }, [data]);

  useEffect(() => {
    function onPointerMove(event: PointerEvent) {
      pointer.current.x = (event.clientX / window.innerWidth) * 2 - 1;
      pointer.current.y = (event.clientY / window.innerHeight) * 2 - 1;
    }
    if (!reducedMotion) window.addEventListener('pointermove', onPointerMove);
    return () => window.removeEventListener('pointermove', onPointerMove);
  }, [reducedMotion]);

  useEffect(() => {
    lineMaterial.current?.color.set(palette.line);
    if (lineMaterial.current) lineMaterial.current.opacity = palette.lineOpacity;
    chordMaterial.current?.color.set(palette.line);
    if (chordMaterial.current) chordMaterial.current.opacity = palette.chordOpacity;
    nodeMaterial.current?.color.set(palette.node);
    focalMaterial.current?.color.set(palette.focal);
  }, [palette]);

  useEffect(() => {
    return () => {
      geometries.nodes.dispose();
      geometries.focal.dispose();
      geometries.lines.dispose();
      geometries.chords.dispose();
    };
  }, [geometries]);

  useFrame((_, delta) => {
    const node = group.current;
    if (node === null || reducedMotion) return;
    const clamped = Math.min(delta, 0.05);
    node.rotation.y += clamped * ROTATION_SPEED;
    const targetX = pointer.current.y * POINTER_TILT;
    const targetY = pointer.current.x * POINTER_TILT * 1.2;
    const damp = 1 - Math.exp(-clamped * 2);
    tilt.current.x += (targetX - tilt.current.x) * damp;
    tilt.current.y += (targetY - tilt.current.y) * damp;
    node.rotation.x = tilt.current.x;
    node.rotation.z = tilt.current.y * 0.4;
  });

  return (
    <group ref={group}>
      <lineSegments geometry={geometries.lines}>
        <lineBasicMaterial ref={lineMaterial} transparent depthWrite={false} />
      </lineSegments>
      <lineSegments geometry={geometries.chords}>
        <lineBasicMaterial ref={chordMaterial} transparent depthWrite={false} />
      </lineSegments>
      <points geometry={geometries.nodes}>
        <pointsMaterial
          ref={nodeMaterial}
          size={0.075}
          map={sprite}
          transparent
          opacity={0.9}
          depthWrite={false}
          sizeAttenuation
        />
      </points>
      <points geometry={geometries.focal}>
        <pointsMaterial
          ref={focalMaterial}
          size={0.17}
          map={sprite}
          transparent
          depthWrite={false}
          sizeAttenuation
        />
      </points>
    </group>
  );
}

export function HeroVisual() {
  const dark = useDarkMode();
  const reducedMotion = usePrefersReducedMotion();
  const palette = dark ? DARK_PALETTE : LIGHT_PALETTE;
  const data = useMemo(() => buildTopology(), []);
  const sprite = useMemo(() => makeNodeSprite(), []);

  useEffect(() => () => sprite.dispose(), [sprite]);

  return (
    <div
      data-testid="hero-visual"
      data-nodes={data.nodeCount}
      data-connections={Math.round(data.connectionCount)}
      className="h-full w-full"
    >
      <Canvas
        dpr={[1, 1.5]}
        camera={{ position: [0, 0.1, 6.2], fov: 40 }}
        gl={{ antialias: true, alpha: true, powerPreference: 'low-power' }}
        frameloop={reducedMotion ? 'demand' : 'always'}
      >
        <Topology data={data} palette={palette} reducedMotion={reducedMotion} sprite={sprite} />
      </Canvas>
    </div>
  );
}
