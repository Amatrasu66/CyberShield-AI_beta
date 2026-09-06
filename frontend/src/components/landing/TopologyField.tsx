import { useEffect, useRef } from 'react';
import * as THREE from 'three';

/**
 * Phase 7.2 — React-native ThreeUI topology field.
 *
 * Ports ONLY the topology rendering implementation from the authored
 * topology demo page (ThreeUI source revision 40eb5bac81e3) into a React
 * component mounted directly in the hero DOM. No iframe, no embedded
 * document, no CDN.
 *
 * Authored logic retained:
 * - 120-node Fibonacci sphere (phi = acos(-1 + 2i/N), theta = sqrt(N*PI)*phi)
 * - connection threshold 0.45 with alpha = (1 - dist/threshold) * 0.8
 * - additive blending, depthWrite false, line opacity 0.65
 * - per-node pulse (baseSize 1.0–2.5, pulseSpeed 0.015–0.035, random offset)
 * - node opacity 0.4 + pulse * 0.6
 * - continuous rotation (y = t*0.0018, x = 0.2, z = t*0.0006, t += 1/frame)
 * - fog 0x0a0a0a (300, 950), camera fov 60 / near 1 / far 2000 at z 650
 *
 * Intentionally NOT carried over: header, hero copy, floating metric cards,
 * avatars, demo labels, footer, Tailwind/Iconify/Three.js CDNs, Google Fonts,
 * canvasGlow DOM, floaters animation.
 *
 * Seamless integration: transparent WebGL background (setClearColor 0,0) so
 * the hero background shows through — no opaque card. Ink color adapts
 * locally to the app theme (html.dark) without touching the global theme.
 */

const NODE_COUNT = 120;
const CONNECTION_THRESHOLD = 0.45;

function isDarkTheme(): boolean {
  if (typeof document === 'undefined') return true;
  return document.documentElement.classList.contains('dark');
}

export function TopologyField() {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    if (!mount) return undefined;

    const reducedMotion =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // --- Renderer (transparent so the hero background shows through) ---
    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.domElement.setAttribute('aria-hidden', 'true');
    renderer.domElement.style.display = 'block';
    renderer.domElement.style.width = '100%';
    renderer.domElement.style.height = '100%';
    mount.appendChild(renderer.domElement);

    // --- Scene / camera (authored values) ---
    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0a0a0a, 300, 950);
    const camera = new THREE.PerspectiveCamera(60, 1, 1, 2000);
    camera.position.z = 650;

    const group = new THREE.Group();
    scene.add(group);

    // --- Nodes: authored 120-node Fibonacci sphere ---
    const nodeGeo = new THREE.SphereGeometry(1, 16, 16);
    const nodes: THREE.Mesh<THREE.SphereGeometry, THREE.MeshBasicMaterial>[] = [];
    for (let i = 0; i < NODE_COUNT; i += 1) {
      const phi = Math.acos(-1 + (2 * i) / NODE_COUNT);
      const theta = Math.sqrt(NODE_COUNT * Math.PI) * phi;
      const material = new THREE.MeshBasicMaterial({
        color: 0xffffff,
        transparent: true,
        opacity: 0.9,
      });
      const mesh = new THREE.Mesh(nodeGeo, material);
      mesh.position.set(
        Math.cos(theta) * Math.sin(phi),
        Math.sin(theta) * Math.sin(phi),
        Math.cos(phi),
      );
      mesh.userData = {
        baseSize: Math.random() * 1.5 + 1.0,
        pulseSpeed: Math.random() * 0.02 + 0.015,
        pulseOffset: Math.random() * Math.PI * 2,
      };
      group.add(mesh);
      nodes.push(mesh);
    }

    // --- Lines: authored threshold graph, alpha-weighted vertex colors ---
    const linePos: number[] = [];
    const lineAlphas: number[] = [];
    for (let i = 0; i < NODE_COUNT; i += 1) {
      for (let j = i + 1; j < NODE_COUNT; j += 1) {
        const dist = nodes[i].position.distanceTo(nodes[j].position);
        if (dist < CONNECTION_THRESHOLD) {
          linePos.push(
            nodes[i].position.x,
            nodes[i].position.y,
            nodes[i].position.z,
            nodes[j].position.x,
            nodes[j].position.y,
            nodes[j].position.z,
          );
          const alpha = (1 - dist / CONNECTION_THRESHOLD) * 0.8;
          lineAlphas.push(alpha, alpha);
        }
      }
    }
    const lineGeo = new THREE.BufferGeometry();
    lineGeo.setAttribute('position', new THREE.Float32BufferAttribute(linePos, 3));
    const colorArray = new Float32Array(lineAlphas.length * 3);
    lineGeo.setAttribute('color', new THREE.BufferAttribute(colorArray, 3));
    const lineMat = new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      opacity: 0.65,
    });
    const lines = new THREE.LineSegments(lineGeo, lineMat);
    group.add(lines);

    // --- Local theme handling (no global theme changes) ---
    const applyTheme = () => {
      const dark = isDarkTheme();
      const ink = dark ? new THREE.Color(0xffffff) : new THREE.Color(0x3a4358);
      for (const node of nodes) node.material.color.copy(ink);
      const attr = lineGeo.getAttribute('color') as THREE.BufferAttribute;
      const arr = attr.array as Float32Array;
      for (let k = 0; k < lineAlphas.length; k += 1) {
        arr[k * 3] = ink.r * lineAlphas[k];
        arr[k * 3 + 1] = ink.g * lineAlphas[k];
        arr[k * 3 + 2] = ink.b * lineAlphas[k];
      }
      attr.needsUpdate = true;
      if (scene.fog) scene.fog.color.set(dark ? 0x0a0a0a : 0xf5f5ff);
    };
    applyTheme();
    const themeObserver =
      typeof MutationObserver !== 'undefined'
        ? new MutationObserver(applyTheme)
        : null;
    themeObserver?.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    });

    // --- Container-relative sizing: compact sphere, lots of negative space ---
    const resize = () => {
      const width = mount.clientWidth || 1;
      const height = mount.clientHeight || 1;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
      // World-space radius proportional to the container so the sphere stays
      // compact (~2/3 of the minor axis) at any breakpoint.
      const radius = Math.min(width, height) * 0.475;
      group.scale.set(radius, radius, radius);
      group.position.set(0, 0, 0);
    };
    resize();
    const resizeObserver =
      typeof ResizeObserver !== 'undefined' ? new ResizeObserver(resize) : null;
    resizeObserver?.observe(mount);
    window.addEventListener('resize', resize);

    // --- Animation: authored loop (refs only, no React state per frame) ---
    let time = 0;
    let frameId = 0;
    const renderFrame = () => {
      group.rotation.y = time * 0.0018;
      group.rotation.x = 0.2;
      group.rotation.z = time * 0.0006;
      const groupScale = group.scale.x || 1;
      for (const mesh of nodes) {
        const p = mesh.userData as {
          baseSize: number;
          pulseSpeed: number;
          pulseOffset: number;
        };
        const pulse = (Math.sin(time * p.pulseSpeed + p.pulseOffset) + 1) / 2;
        const targetRadius = p.baseSize + pulse * 1.8;
        const scale = targetRadius / groupScale;
        mesh.scale.set(scale, scale, scale);
        mesh.material.opacity = 0.4 + pulse * 0.6;
      }
      renderer.render(scene, camera);
    };

    if (reducedMotion) {
      // Static topology frame: freeze mid-pulse instead of animating.
      time = 60;
      renderFrame();
    } else {
      const animate = () => {
        frameId = requestAnimationFrame(animate);
        time += 1;
        renderFrame();
      };
      animate();
    }

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener('resize', resize);
      resizeObserver?.disconnect();
      themeObserver?.disconnect();
      group.traverse((child) => {
        const mesh = child as THREE.Mesh;
        if (mesh.isMesh) {
          (mesh.material as THREE.Material).dispose();
        }
      });
      lineMat.dispose();
      lineGeo.dispose();
      nodeGeo.dispose();
      renderer.dispose();
      if (renderer.domElement.parentElement === mount) {
        mount.removeChild(renderer.domElement);
      }
    };
  }, []);

  return (
    <div
      ref={mountRef}
      aria-hidden="true"
      data-testid="hero-topology"
      className="pointer-events-none relative h-full w-full overflow-hidden bg-transparent"
    >
      {/* Whisper of a local radial lift so the field melts into the hero —
          not a card, no border, fully transparent edges. */}
      <div
        aria-hidden="true"
        className="absolute inset-0 bg-[radial-gradient(closest-side,rgba(58,67,88,0.10),transparent)] dark:bg-[radial-gradient(closest-side,rgba(255,255,255,0.06),transparent)]"
      />
    </div>
  );
}
